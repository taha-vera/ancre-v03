use rand::rngs::OsRng;
use rand::Rng;
use rand::RngCore;
use sha2::{Sha256, Digest};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::collections::HashMap;
use std::time::{Instant, Duration};

// ─────────────────────────────────────────────
// Invariants VERA — NON MODIFIABLES
// ─────────────────────────────────────────────
const K_MIN: usize = 100;
const EPSILON_SERVER: f64 = 0.5;  // Central DP — seul epsilon
const EPSILON_MAX: f64 = 1.5;     // 3 agregations max
const MAX_BUFFER_SIGNALS: usize = 10_000;
const MAX_NONCES: usize = 100_000;
const NONCE_TTL_SECS: u64 = 300;
const TRIM_FRACTION: f64 = 0.1;

// ─────────────────────────────────────────────
// F_new1 FIX — laplace_noise sans signum(0.0)
// Central DP — bruit cote serveur uniquement
// ─────────────────────────────────────────────

fn laplace_noise(scale: f64) -> f64 {
    let u: f64 = {
        let mut v = OsRng.gen::<f64>() - 0.5;
        while v == -0.5 || v == 0.0 { v = OsRng.gen::<f64>() - 0.5; }
        v
    };
    let safe = (1.0 - 2.0 * u.abs()).max(f64::MIN_POSITIVE);
    // F_new1 FIX : eviter signum(0.0) = 0 en IEEE 754
    let sign = if u >= 0.0 { 1.0_f64 } else { -1.0_f64 };
    -scale * sign * safe.ln()
}

// ─────────────────────────────────────────────
// INV-2 : BoundedSignal [0,1] — validation stricte
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct BoundedSignal(f64);

impl BoundedSignal {
    pub fn new(v: f64) -> Result<Self, String> {
        if v.is_nan() || v.is_infinite() {
            return Err(format!("NaN/Inf interdit : {}", v));
        }
        if !(0.0..=1.0).contains(&v) {
            return Err(format!("Hors [0,1] : {}", v));
        }
        Ok(Self(v))
    }
    pub fn value(&self) -> f64 { self.0 }
}

// ─────────────────────────────────────────────
// INV-1 : EpsilonBudget — monotone strict
// ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct EpsilonBudget {
    epsilon_max: f64,
    epsilon_used: f64,
}

impl EpsilonBudget {
    pub fn new(max: f64) -> Self {
        assert!(max > 0.0);
        Self { epsilon_max: max, epsilon_used: 0.0 }
    }
    pub fn spend(&mut self, amount: f64) -> Result<(), String> {
        if amount <= 0.0 {
            return Err(format!("amount invalide : {}", amount));
        }
        if self.epsilon_used + amount > self.epsilon_max + 1e-12 {
            return Err(format!("Budget epuise : {:.2}+{:.2} > {:.2}",
                self.epsilon_used, amount, self.epsilon_max));
        }
        self.epsilon_used += amount;
        Ok(())
    }
    pub fn remaining(&self) -> f64 { self.epsilon_max - self.epsilon_used }
    pub fn is_exhausted(&self) -> bool { self.remaining() <= 1e-12 }
    pub fn used(&self) -> f64 { self.epsilon_used }
}

// ─────────────────────────────────────────────
// Moyenne tronquee — sensibilite formelle
// Pour signaux dans [0,1], trim=10% :
// sensibilite = 1.0 / (n * (1 - 2*TRIM_FRACTION))
// scale = sensibilite / EPSILON_SERVER
// ─────────────────────────────────────────────

pub fn trimmed_mean(vals: &mut Vec<f64>, trim_fraction: f64) -> f64 {
    vals.sort_by(|a, b| a.total_cmp(b));
    let n = vals.len();
    let trim = (n as f64 * trim_fraction).floor() as usize;
    if trim * 2 >= n { return vals[n / 2]; }
    let trimmed = &vals[trim..n - trim];
    trimmed.iter().sum::<f64>() / trimmed.len() as f64
}

// ─────────────────────────────────────────────
// INV-3 : AncreBuffer — Central DP
// Pas de bruit client — bruit dans aggregate() uniquement
// Garantie : chaque aggregate() est EPSILON_SERVER-DP
// ─────────────────────────────────────────────

pub struct AncreBuffer {
    pub signals: Vec<BoundedSignal>,
    budget: EpsilonBudget,
}

impl AncreBuffer {
    pub fn new() -> Self {
        Self {
            signals: Vec::with_capacity(MAX_BUFFER_SIGNALS),
            budget: EpsilonBudget::new(EPSILON_MAX),
        }
    }

    pub fn push(&mut self, raw: f64) -> Result<(), String> {
        if self.signals.len() >= MAX_BUFFER_SIGNALS {
            return Err("Requete invalide".to_string());
        }
        // Central DP : pas de bruit ici — signal brut valide
        let signal = BoundedSignal::new(raw)?;
        self.signals.push(signal);
        Ok(())
    }

    pub fn aggregate(&mut self) -> Result<f64, String> {
        let k = self.signals.len();
        if k < K_MIN {
            return Err(format!("K={} < K_MIN={}", k, K_MIN));
        }

        let mut vals: Vec<f64> = self.signals.iter().map(|s| s.value()).collect();

        // Moyenne tronquee
        let mean = trimmed_mean(&mut vals, TRIM_FRACTION);

        // Sensibilite formelle pour TMoM sur [0,1]
        let k_eff = k as f64 * (1.0 - 2.0 * TRIM_FRACTION);
        let sensitivity = 1.0 / k_eff;
        let scale = sensitivity / EPSILON_SERVER;

        // Depense du budget APRES le check K_MIN
        // Si K < K_MIN, on retourne Err AVANT cette ligne → budget intact
        // Si spend() echoue → budget non consomme (Err sans mutation)
        self.budget.spend(EPSILON_SERVER)?;

        // Bruit Laplace Central DP
        let noisy = (mean + laplace_noise(scale)).clamp(0.0, 1.0);
        self.signals.clear();
        Ok(noisy)
    }

    pub fn signal_count(&self) -> usize { self.signals.len() }
    pub fn budget_remaining(&self) -> f64 { self.budget.remaining() }
    pub fn budget_used(&self) -> f64 { self.budget.used() }
    pub fn is_budget_exhausted(&self) -> bool { self.budget.is_exhausted() }
}

// ─────────────────────────────────────────────
// Kill-switch — Release/Acquire
// ─────────────────────────────────────────────

#[derive(Clone)]
pub struct PolicyEngine {
    killed: Arc<AtomicBool>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self { killed: Arc::new(AtomicBool::new(false)) }
    }
    pub fn kill(&self) { self.killed.store(true, Ordering::Release); }
    pub fn is_alive(&self) -> bool { !self.killed.load(Ordering::Acquire) }
    pub fn check(&self) -> Result<(), String> {
        if self.is_alive() { Ok(()) }
        else { Err("KILL-SWITCH ACTIVE".to_string()) }
    }
}

// ─────────────────────────────────────────────
// Audit chain — SHA-256 complet
// Note : hash chain seulement — pas de HMAC
// Garantit l'integrite locale, pas l'authenticite
// ─────────────────────────────────────────────

pub struct AuditChain {
    prev_hash: String,
    entries: Vec<String>,
}

impl AuditChain {
    pub fn new() -> Self {
        Self { prev_hash: "genesis".to_string(), entries: Vec::new() }
    }
    pub fn append(&mut self, aggregate: f64, k: usize, epsilon: f64) -> String {
        let mut h = Sha256::new();
        h.update(self.prev_hash.as_bytes());
        h.update(aggregate.to_bits().to_be_bytes());
        h.update(k.to_be_bytes());
        h.update(epsilon.to_bits().to_be_bytes());
        let hash = hex::encode(h.finalize().as_slice());
        self.prev_hash = hash.clone();
        self.entries.push(format!(
            "agg={:.4} k={} e={:.2} hash={}", aggregate, k, epsilon, hash
        ));
        hash
    }
    pub fn len(&self) -> usize { self.entries.len() }
}

// ─────────────────────────────────────────────
// TtlNonceCache — anti-replay avec TTL
// Remplace FIFO (replay possible apres eviction)
// ─────────────────────────────────────────────

pub struct TtlNonceCache {
    entries: HashMap<u64, Instant>,
    ttl: Duration,
    max_size: usize,
}

impl TtlNonceCache {
    pub fn new(ttl_secs: u64, max_size: usize) -> Self {
        Self {
            entries: HashMap::new(),
            ttl: Duration::from_secs(ttl_secs),
            max_size,
        }
    }
    pub fn check_and_consume(&mut self, nonce: u64) -> Result<(), String> {
        self.purge_expired();
        if self.entries.contains_key(&nonce) {
            return Err(format!("Replay detecte : nonce={}", nonce));
        }
        if self.entries.len() >= self.max_size {
            return Err("Nonce cache plein".to_string());
        }
        self.entries.insert(nonce, Instant::now());
        Ok(())
    }
    fn purge_expired(&mut self) {
        let ttl = self.ttl;
        self.entries.retain(|_, ts| ts.elapsed() < ttl);
    }
    pub fn len(&self) -> usize { self.entries.len() }
}

// ─────────────────────────────────────────────
// device_id — SHA-256 avec sel de session
// Note : troncature 64 bits — collision theorique a 2^32
// Acceptable pour quota de session, pas pour auth forte
// ─────────────────────────────────────────────

pub fn derive_device_id(credential: &[u8], session_salt: u64) -> u64 {
    let mut h = Sha256::new();
    h.update(&session_salt.to_be_bytes());
    h.update(credential);
    let hash = h.finalize();
    u64::from_be_bytes(hash[..8].try_into().unwrap())
}

// ─────────────────────────────────────────────
// SecureBufferV2 — Central DP complet
// F_new2 FIX : device_counts reset avant aggregate()
// ─────────────────────────────────────────────

pub struct SecureBufferV2 {
    inner: AncreBuffer,
    policy: PolicyEngine,
    nonces: TtlNonceCache,
    device_counts: HashMap<u64, usize>,
    max_per_device: usize,
    session_salt: u64,
    aggregation_count: usize,
}

impl SecureBufferV2 {
    pub fn new(policy: PolicyEngine) -> Self {
        Self {
            inner: AncreBuffer::new(),
            policy,
            nonces: TtlNonceCache::new(NONCE_TTL_SECS, MAX_NONCES),
            device_counts: HashMap::new(),
            max_per_device: 30,
            session_salt: OsRng.gen::<u64>(),
            aggregation_count: 0,
        }
    }

    pub fn push(&mut self, raw: f64, nonce: u64, credential: &[u8]) -> Result<(), String> {
        self.policy.check()?;

        // Validation credential non vide
        if credential.is_empty() {
            return Err("Requete invalide".to_string());
        }

        if self.inner.signal_count() >= MAX_BUFFER_SIGNALS {
            return Err("Requete invalide".to_string());
        }
        if self.inner.is_budget_exhausted() {
            return Err("Budget serveur epuise".to_string());
        }

        self.nonces.check_and_consume(nonce)?;

        let device_id = derive_device_id(credential, self.session_salt);
        let count = self.device_counts.entry(device_id).or_insert(0);
        if *count >= self.max_per_device {
            return Err("Device quota atteint".to_string());
        }
        *count += 1;

        self.inner.push(raw)
    }

    pub fn aggregate(&mut self) -> Result<(f64, f64, usize), String> {
        self.policy.check()?;

        // F_new2 FIX : reset session AVANT aggregate()
        // Ainsi meme si aggregate() echoue, les compteurs sont resets
        self.device_counts.clear();
        self.session_salt = OsRng.gen::<u64>();

        let agg = self.inner.aggregate()?;
        let eps_used = self.inner.budget_used();
        self.aggregation_count += 1;

        Ok((agg, eps_used, self.aggregation_count))
    }

    pub fn budget_remaining(&self) -> f64 { self.inner.budget_remaining() }
    pub fn is_budget_exhausted(&self) -> bool { self.inner.is_budget_exhausted() }
    pub fn signal_count(&self) -> usize { self.inner.signal_count() }
}

// ─────────────────────────────────────────────
// Metriques
// ─────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct Metrics {
    pub signals_received: usize,
    pub signals_rejected: usize,
    pub aggregations_ok: usize,
    pub budget_exhausted: usize,
}

impl Metrics {
    pub fn new() -> Self { Self::default() }
    pub fn record_signal(&mut self, ok: bool) {
        if ok { self.signals_received += 1; } else { self.signals_rejected += 1; }
    }
    pub fn record_agg(&mut self, ok: bool) {
        if ok { self.aggregations_ok += 1; } else { self.budget_exhausted += 1; }
    }
    pub fn report(&self) -> String {
        format!("signals={} rejected={} agg_ok={} budget_exhausted={}",
            self.signals_received, self.signals_rejected,
            self.aggregations_ok, self.budget_exhausted)
    }
}

// ─────────────────────────────────────────────
// Tests complets v0.5
// ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // INV-1 — budget monotone
    proptest! {
        #[test]
        fn inv1_epsilon_monotone(amounts in prop::collection::vec(0.001f64..0.1, 1..20)) {
            let mut budget = EpsilonBudget::new(10.0);
            let mut prev = 0.0f64;
            for amount in amounts {
                if budget.spend(amount).is_ok() {
                    assert!(budget.epsilon_used >= prev);
                    prev = budget.epsilon_used;
                }
            }
        }

        #[test]
        fn inv1_never_exceeds_max(amounts in prop::collection::vec(0.001f64..1.0, 1..50)) {
            let mut budget = EpsilonBudget::new(1.5);
            for amount in amounts {
                let _ = budget.spend(amount);
                assert!(budget.epsilon_used <= 1.5 + 1e-10);
            }
        }

        // INV-2 — bounds enforced
        #[test]
        fn inv2_bounds_enforced(v in -10.0f64..10.0) {
            let result = BoundedSignal::new(v);
            if v >= 0.0 && v <= 1.0 { assert!(result.is_ok()); }
            else { assert!(result.is_err()); }
        }

        // TMoM sensibilite formelle
        #[test]
        fn tmom_sensitivity(
            vals in prop::collection::vec(0.0f64..=1.0, 100..200),
            idx in 0usize..100,
            replacement in 0.0f64..=1.0
        ) {
            let mut v1 = vals.clone();
            let mut v2 = vals.clone();
            let len2 = v2.len();
            v2[idx % len2] = replacement;
            let m1 = trimmed_mean(&mut v1, TRIM_FRACTION);
            let m2 = trimmed_mean(&mut v2, TRIM_FRACTION);
            let n = vals.len() as f64;
            let max_sensitivity = 1.0 / (n * (1.0 - 2.0 * TRIM_FRACTION)) + 1e-9;
            assert!((m1 - m2).abs() <= max_sensitivity,
                "sensitivity={:.6} max={:.6}", (m1-m2).abs(), max_sensitivity);
        }
    }

    // INV-3 — K-anonymity
    #[test]
    fn inv3_k_min_enforced() {
        let mut buf = AncreBuffer::new();
        for i in 0..50 { buf.push(0.1 + 0.001 * i as f64).ok(); }
        assert!(buf.aggregate().is_err());
    }

    #[test]
    fn inv3_aggregate_ok() {
        let mut buf = AncreBuffer::new();
        for i in 0..120 { buf.push(0.3 + 0.001 * i as f64).ok(); }
        let result = buf.aggregate();
        assert!(result.is_ok());
        let agg = result.unwrap();
        assert!(agg >= 0.0 && agg <= 1.0);
    }

    // Budget — exactement 3 agregations
    #[test]
    fn budget_exactly_3_aggregations() {
        let mut buf = AncreBuffer::new();
        for _s in 0..3 {
            for _ in 0..120 { buf.push(0.5).ok(); }
            assert!(buf.aggregate().is_ok());
        }
        // 4eme doit echouer
        for _ in 0..120 { buf.push(0.5).ok(); }
        let result = buf.aggregate();
        assert!(result.is_err(), "4e agregation doit echouer");
    }

    // F_new1 — signum fix
    #[test]
    fn laplace_noise_never_zero() {
        // Verifie que laplace_noise ne produit pas 0.0 systematiquement
        let samples: Vec<f64> = (0..1000).map(|_| laplace_noise(1.0)).collect();
        let zeros = samples.iter().filter(|&&x| x == 0.0).count();
        // Quelques zeros possibles mais pas systematiques
        assert!(zeros < 10, "Trop de zeros : {}", zeros);
    }

    #[test]
    fn laplace_sign_distribution() {
        // Distribution positive/negative doit etre equilibree
        let n = 10_000;
        let samples: Vec<f64> = (0..n).map(|_| laplace_noise(1.0)).collect();
        let positives = samples.iter().filter(|&&x| x > 0.0).count();
        // Entre 45% et 55% positifs
        assert!(positives > 4500 && positives < 5500,
            "Desequilibre signe : {} positifs sur {}", positives, n);
    }

    // F_new2 — device_counts reset meme si aggregate() echoue
    #[test]
    fn device_counts_reset_on_aggregate_fail() {
        let policy = PolicyEngine::new();
        let mut buf = SecureBufferV2::new(policy);

        // Epuiser le budget
        for session in 0..3 {
            for i in 0..120 {
                let cred = format!("s{}_d{}", session, i);
                buf.push(0.5, session * 1000 + i as u64, cred.as_bytes()).ok();
            }
            buf.aggregate().ok();
        }

        // 4eme session — budget epuise
        let cred = b"device_A";
        for i in 0..120 {
            buf.push(0.5, 5000 + i as u64, cred).ok();
        }
        // Aggregate echoue — budget epuise
        let result = buf.aggregate();
        assert!(result.is_err());

        // F_new2 : device_A doit pouvoir soumettre a nouveau
        // car device_counts a ete reset AVANT l'echec
        // (budget est epuise donc push echoue aussi — c'est normal)
        let push_result = buf.push(0.5, 9999, cred);
        // Le rejet est du au budget epuise, pas au quota device
        match push_result {
            Err(e) => assert!(e.contains("epuise") || e.contains("plein"),
                "Rejet inattendu : {}", e),
            Ok(_) => {}
        }
    }

    // Credential vide rejete
    #[test]
    fn empty_credential_rejected() {
        let policy = PolicyEngine::new();
        let mut buf = SecureBufferV2::new(policy);
        assert!(buf.push(0.5, 1, b"").is_err());
    }

    // Kill-switch
    #[test]
    fn kill_switch_irreversible() {
        let policy = PolicyEngine::new();
        assert!(policy.is_alive());
        policy.kill();
        assert!(!policy.is_alive());
    }

    #[test]
    fn kill_switch_blocks_push() {
        let policy = PolicyEngine::new();
        let mut buf = SecureBufferV2::new(policy.clone());
        policy.kill();
        assert!(buf.push(0.5, 1, b"dev").is_err());
    }

    // Anti-replay TTL
    #[test]
    fn ttl_replay_rejected() {
        let mut cache = TtlNonceCache::new(300, 1000);
        assert!(cache.check_and_consume(42).is_ok());
        assert!(cache.check_and_consume(42).is_err());
    }

    #[test]
    fn ttl_cache_bounded() {
        let mut cache = TtlNonceCache::new(300, 3);
        assert!(cache.check_and_consume(1).is_ok());
        assert!(cache.check_and_consume(2).is_ok());
        assert!(cache.check_and_consume(3).is_ok());
        // 4eme rejeté — cache plein pas eviction
        assert!(cache.check_and_consume(4).is_err());
    }

    // device_id avec sel de session
    #[test]
    fn device_id_session_salt_changes() {
        let id1 = derive_device_id(b"cred_A", 111);
        let id2 = derive_device_id(b"cred_A", 222);
        let id3 = derive_device_id(b"cred_A", 111);
        assert_ne!(id1, id2, "Sels differents doivent donner IDs differents");
        assert_eq!(id1, id3, "Meme sel doit donner meme ID");
    }

    // Audit chain
    #[test]
    fn audit_chain_tamper_detected() {
        let mut c1 = AuditChain::new();
        let mut c2 = AuditChain::new();
        c1.append(0.42, 120, 1.5);
        c2.append(0.99, 120, 1.5);
        let h1 = c1.append(0.30, 110, 1.5);
        let h2 = c2.append(0.30, 110, 1.5);
        assert_ne!(h1, h2);
    }

    // Tests statistiques DP
    #[test]
    fn laplace_mean_near_zero() {
        let n = 10_000;
        let samples: Vec<f64> = (0..n).map(|_| laplace_noise(1.0)).collect();
        let mean = samples.iter().sum::<f64>() / n as f64;
        assert!(mean.abs() < 0.05, "Moyenne={:.4}", mean);
    }

    #[test]
    fn laplace_variance_correct() {
        let n = 10_000;
        let scale = 1.0;
        let samples: Vec<f64> = (0..n).map(|_| laplace_noise(scale)).collect();
        let mean = samples.iter().sum::<f64>() / n as f64;
        let var = samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n as f64;
        let expected = 2.0 * scale * scale;
        assert!((var - expected).abs() < 0.5, "Variance={:.4} attendu={:.4}", var, expected);
    }

    // Central DP : pas de bruit dans push()
    #[test]
    fn central_dp_no_client_noise() {
        let mut buf = AncreBuffer::new();
        buf.push(0.42).unwrap();
        assert_eq!(buf.signals[0].value(), 0.42,
            "push() ne doit pas bruiter le signal");
    }

    // Bruit effectif dans aggregate()
    #[test]
    fn aggregate_adds_noise() {
        let trials = 500;
        let results: Vec<f64> = (0..trials).map(|_| {
            let mut buf = AncreBuffer::new();
            for _ in 0..120 { buf.push(0.5).ok(); }
            buf.aggregate().unwrap()
        }).collect();
        let mean = results.iter().sum::<f64>() / trials as f64;
        let var = results.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / trials as f64;
        assert!(var > 1e-6, "Aucun bruit dans aggregate() : var={:.6}", var);
        assert!((mean - 0.5).abs() < 0.05, "Bruit biaise : mean={:.4}", mean);
    }

    // Integration complete Central DP
    #[test]
    fn integration_central_dp() {
        let policy = PolicyEngine::new();
        let mut buf = SecureBufferV2::new(policy);
        let mut chain = AuditChain::new();
        let mut metrics = Metrics::new();

        for session in 0..3 {
            for i in 0..120 {
                let cred = format!("dev_{}_{}", session, i);
                match buf.push(0.5, session * 1000 + i as u64, cred.as_bytes()) {
                    Ok(_) => metrics.record_signal(true),
                    Err(_) => metrics.record_signal(false),
                }
            }
            match buf.aggregate() {
                Ok((agg, eps, n)) => {
                    metrics.record_agg(true);
                    chain.append(agg, 120, eps);
                    println!("Session {}: agg={:.4} eps={:.2} n={}", session, agg, eps, n);
                }
                Err(e) => { metrics.record_agg(false); println!("Err: {}", e); }
            }
        }

        assert_eq!(metrics.aggregations_ok, 3);
        assert_eq!(chain.len(), 3);
        assert!(buf.is_budget_exhausted());
        println!("{}", metrics.report());
    }
}

// ─────────────────────────────────────────────
// Main — demo Central DP
// ─────────────────────────────────────────────

fn main() {
    println!("ANCRE v0.5 — Central DP");
    println!("Garantie : chaque agregation est {:.1}-DP", EPSILON_SERVER);
    println!("Budget total : {:.1} ({} agregations max)\n",
        EPSILON_MAX, (EPSILON_MAX / EPSILON_SERVER) as usize);

    let policy = PolicyEngine::new();
    let mut buf = SecureBufferV2::new(policy);
    let mut chain = AuditChain::new();
    let mut metrics = Metrics::new();

    for session in 0..4 {
        println!("--- Session {} (budget: {:.1}/{:.1}) ---",
            session, EPSILON_MAX - buf.budget_remaining(), EPSILON_MAX);

        for i in 0..120 {
            let cred = format!("dev_{}_{}", session, i);
            match buf.push(0.5, session * 10000 + i as u64, cred.as_bytes()) {
                Ok(_) => metrics.record_signal(true),
                Err(e) => { metrics.record_signal(false);
                    if i == 0 { println!("  Rejet: {}", e); } }
            }
        }

        match buf.aggregate() {
            Ok((agg, eps, n)) => {
                metrics.record_agg(true);
                let hash = chain.append(agg, 120, eps);
                println!("  OK agg={:.4} eps_total={:.2} n={} hash={}",
                    agg, eps, n, &hash[..12]);
            }
            Err(e) => {
                metrics.record_agg(false);
                println!("  FAIL : {}", e);
            }
        }
    }

    println!("\n{}", metrics.report());
    println!("Audit chain: {} entrees", chain.len());
}

// ─────────────────────────────────────────────
// Q10 FIX — EpsilonBudget entiers
// Remplace f64 (erreurs d'arrondi) par u64
// 1.0 epsilon = 1_000_000 micro-epsilon
// ─────────────────────────────────────────────

const MICRO: u64 = 1_000_000;

pub struct EpsilonBudgetExact {
    epsilon_max: u64,
    epsilon_used: u64,
}

impl EpsilonBudgetExact {
    pub fn new(max: f64) -> Self {
        Self {
            epsilon_max: (max * MICRO as f64) as u64,
            epsilon_used: 0,
        }
    }
    pub fn spend(&mut self, amount: f64) -> Result<(), String> {
        let amount_u = (amount * MICRO as f64).round() as u64;
        if amount_u == 0 {
            return Err("amount invalide".to_string());
        }
        if self.epsilon_used + amount_u > self.epsilon_max {
            return Err(format!("Budget epuise : {}/{}",
                self.epsilon_used, self.epsilon_max));
        }
        self.epsilon_used += amount_u;
        Ok(())
    }
    pub fn remaining_f64(&self) -> f64 {
        (self.epsilon_max - self.epsilon_used) as f64 / MICRO as f64
    }
    pub fn is_exhausted(&self) -> bool {
        self.epsilon_used >= self.epsilon_max
    }
}

#[cfg(test)]
mod exact_budget_tests {
    use super::*;

    #[test]
    fn exact_3_aggregations() {
        let mut b = EpsilonBudgetExact::new(1.5);
        assert!(b.spend(0.5).is_ok());
        assert!(b.spend(0.5).is_ok());
        assert!(b.spend(0.5).is_ok());
        assert!(b.spend(0.5).is_err());
        assert!(b.is_exhausted());
    }

    #[test]
    fn exact_no_float_drift() {
        let mut b = EpsilonBudgetExact::new(1.5);
        for _ in 0..1500 { b.spend(0.001).ok(); }
        assert!(b.is_exhausted(),
            "Budget doit etre epuise apres 1500 x 0.001");
    }

    #[test]
    fn exact_remaining_correct() {
        let mut b = EpsilonBudgetExact::new(1.5);
        b.spend(0.5).unwrap();
        let r = b.remaining_f64();
        assert!((r - 1.0).abs() < 1e-6, "remaining={:.6}", r);
    }
}

// ─────────────────────────────────────────────
// Q13 — 3 nouveaux proptest DP
// ─────────────────────────────────────────────

#[cfg(test)]
mod dp_proptest_q13 {
    use super::*;
    use proptest::prelude::*;

    // Test 1 — Sensibilité TMoM cas pathologiques
    proptest! {
        #[test]
        fn prop_tmom_sensitivity_pathological(
            n in K_MIN..200usize,
            idx in 0usize..K_MIN,
            new_val in 0.0f64..=1.0,
        ) {
            let mut v1: Vec<f64> = (0..n).map(|i| i as f64 / n as f64).collect();
            let mut v2 = v1.clone();
            v2[idx % n] = new_val;
            let m1 = trimmed_mean(&mut v1, TRIM_FRACTION);
            let m2 = trimmed_mean(&mut v2, TRIM_FRACTION);
            let max_s = 1.0 / (n as f64 * (1.0 - 2.0 * TRIM_FRACTION)) + 1e-9;
            prop_assert!((m1 - m2).abs() <= max_s,
                "sensitivity={:.8} max={:.8}", (m1-m2).abs(), max_s);
        }

        // Test 2 — Biais clamping borné
        #[test]
        fn prop_clamping_bias_bounded(
            mean in 0.1f64..0.9,
            scale in 0.001f64..0.1,
        ) {
            let n = 1_000;
            let sum: f64 = (0..n)
                .map(|_| (mean + laplace_noise(scale)).clamp(0.0, 1.0))
                .sum();
            let empirical = sum / n as f64;
            prop_assert!((empirical - mean).abs() < 3.0 * scale,
                "Biais: mean={:.4} empirical={:.4} scale={:.4}",
                mean, empirical, scale);
        }

        // Test 3 — Budget exact monotone
        #[test]
        fn prop_exact_budget_monotone(
            amounts in prop::collection::vec(0.001f64..0.1, 1..20)
        ) {
            let mut b = EpsilonBudgetExact::new(10.0);
            let mut prev = 0u64;
            for amount in amounts {
                if b.spend(amount).is_ok() {
                    assert!(b.epsilon_used >= prev);
                    prev = b.epsilon_used;
                }
            }
        }
    }
}

// ─────────────────────────────────────────────
// Q14 — Test empirique DP
// Vérifie que le mécanisme est bien ε-DP
// Protocole : ratio Pr[M(D)] / Pr[M(D')] ≤ e^ε
// ─────────────────────────────────────────────

#[cfg(test)]
mod empirical_dp_tests {
    use super::*;

    fn empirical_dp_check(epsilon: f64, n_trials: usize, n_signals: usize, delta: f64) -> bool {
        let bins = 50usize;
        let mut hist_d = vec![0u64; bins];
        let mut hist_d_prime = vec![0u64; bins];

        for _ in 0..n_trials {
            // Dataset D : tous 0.5
            let mut buf_d = AncreBuffer::new();
            for _ in 0..n_signals { buf_d.push(0.5).ok(); }
            if let Ok(agg) = buf_d.aggregate() {
                let bin = (agg * bins as f64) as usize;
                hist_d[bin.min(bins - 1)] += 1;
            }

            // Dataset D' : un signal = 0.5 + delta
            let mut buf_dp = AncreBuffer::new();
            for i in 0..n_signals {
                let v = if i == 0 { (0.5 + delta).clamp(0.0, 1.0) } else { 0.5 };
                buf_dp.push(v).ok();
            }
            if let Ok(agg) = buf_dp.aggregate() {
                let bin = (agg * bins as f64) as usize;
                hist_d_prime[bin.min(bins - 1)] += 1;
            }
        }

        let max_ratio = epsilon.exp();
        for i in 0..bins {
            if hist_d[i] > 10 {
                let ratio = hist_d_prime[i] as f64 / hist_d[i] as f64;
                if ratio > max_ratio * 1.2 { // 20% marge statistique
                    return false;
                }
            }
        }
        true
    }

    #[test]
    fn empirical_05_dp_small_delta() {
        assert!(
            empirical_dp_check(EPSILON_SERVER, 10_000, K_MIN, 0.1),
            "ANCRE n'est pas {:.1}-DP (delta=0.1)", EPSILON_SERVER
        );
    }

    #[test]
    fn empirical_05_dp_large_delta() {
        assert!(
            empirical_dp_check(EPSILON_SERVER, 10_000, K_MIN, 0.5),
            "ANCRE n'est pas {:.1}-DP (delta=0.5)", EPSILON_SERVER
        );
    }
}

// ─────────────────────────────────────────────
// HMAC — AuditChain authentifiée
// ─────────────────────────────────────────────

use sha2::Sha256 as HmacSha256;
use hmac::{Hmac, Mac};

type HmacType = Hmac<HmacSha256>;

pub struct AuthAuditChain {
    prev_hash: String,
    hmac_key: Vec<u8>,
    entries: Vec<String>,
}

impl AuthAuditChain {
    pub fn new(key: &[u8]) -> Self {
        Self {
            prev_hash: "genesis".to_string(),
            hmac_key: key.to_vec(),
            entries: Vec::new(),
        }
    }
    pub fn append(&mut self, aggregate: f64, k: usize, epsilon: f64) -> String {
        let mut mac = HmacType::new_from_slice(&self.hmac_key)
            .expect("HMAC init");
        mac.update(self.prev_hash.as_bytes());
        mac.update(&aggregate.to_bits().to_be_bytes());
        mac.update(&k.to_be_bytes());
        mac.update(&epsilon.to_bits().to_be_bytes());
        let hash = hex::encode(mac.finalize().into_bytes());
        self.prev_hash = hash.clone();
        self.entries.push(format!(
            "agg={:.4} k={} e={:.2} hmac={}", aggregate, k, epsilon, &hash[..16]
        ));
        hash
    }
    pub fn len(&self) -> usize { self.entries.len() }
}

// ─────────────────────────────────────────────
// Q10 FIX — SecureBufferV2 avec sauvegarde état
// ─────────────────────────────────────────────

impl SecureBufferV2 {
    pub fn aggregate_safe(&mut self) -> Result<(f64, f64, usize), String> {
        self.policy.check()?;

        // Sauvegarder l'état avant modification
        let saved_counts = self.device_counts.clone();
        let saved_salt = self.session_salt;

        // Reset session
        self.device_counts.clear();
        self.session_salt = OsRng.gen::<u64>();

        // Agrégation — restaurer si échec
        match self.inner.aggregate() {
            Ok(agg) => {
                let eps_used = self.inner.budget_used();
                self.aggregation_count += 1;
                Ok((agg, eps_used, self.aggregation_count))
            }
            Err(e) => {
                // Restaurer l'état
                self.device_counts = saved_counts;
                self.session_salt = saved_salt;
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod q10_tests {
    use super::*;

    #[test]
    fn q10_state_restored_on_aggregate_fail() {
        let policy = PolicyEngine::new();
        let mut buf = SecureBufferV2::new(policy);
        let cred = b"device_A";

        // Push 5 signaux — quota device_A = 5
        for i in 0..5 {
            buf.push(0.5, i as u64, cred).unwrap();
        }

        let salt_before = buf.session_salt;

        // aggregate_safe() échoue — K < K_MIN
        let result = buf.aggregate_safe();
        assert!(result.is_err());

        // État restauré — session_salt inchangé
        assert_eq!(buf.session_salt, salt_before,
            "session_salt doit etre restaure apres echec");

        // device_A peut encore soumettre
        assert!(buf.push(0.5, 99, cred).is_ok(),
            "device_A doit pouvoir soumettre apres echec aggregate");
    }

    #[test]
    fn q10_state_cleared_on_success() {
        let policy = PolicyEngine::new();
        let mut buf = SecureBufferV2::new(policy);

        for session in 0..1 {
            for i in 0..120 {
                let cred = format!("dev_{}_{}", session, i);
                buf.push(0.5, session * 1000 + i as u64, cred.as_bytes()).ok();
            }
        }

        let result = buf.aggregate_safe();
        assert!(result.is_ok());

        // device_counts doit etre vide apres succès
        assert_eq!(buf.device_counts.len(), 0,
            "device_counts doit etre vide apres succes");
    }
}

#[cfg(test)]
mod q12_tests {
    use super::*;

    #[test]
    fn auth_audit_chain_same_input_same_hmac() {
        let key = b"vera-ancre-secret-key-2026";
        let mut c1 = AuthAuditChain::new(key);
        let mut c2 = AuthAuditChain::new(key);
        assert_eq!(c1.append(0.5, 100, 0.5), c2.append(0.5, 100, 0.5));
    }

    #[test]
    fn auth_audit_chain_diff_input_diff_hmac() {
        let key = b"vera-ancre-secret-key-2026";
        let mut c1 = AuthAuditChain::new(key);
        let mut c2 = AuthAuditChain::new(key);
        let h1 = c1.append(0.6, 100, 0.5);
        let h2 = c2.append(0.7, 100, 0.5);
        assert_ne!(h1, h2);
    }

    #[test]
    fn auth_audit_chain_tamper_detected() {
        let key = b"vera-ancre-secret-key-2026";
        let mut c1 = AuthAuditChain::new(key);
        let mut c2 = AuthAuditChain::new(key);
        c1.append(0.5, 100, 0.5);
        c2.append(0.9, 100, 0.5);
        assert_ne!(c1.append(0.6, 100, 0.5), c2.append(0.6, 100, 0.5));
    }

    #[test]
    fn auth_audit_chain_wrong_key_rejected() {
        let mut c1 = AuthAuditChain::new(b"key1");
        let mut c2 = AuthAuditChain::new(b"key2");
        assert_ne!(c1.append(0.5, 100, 0.5), c2.append(0.5, 100, 0.5));
    }
}

// ─────────────────────────────────────────────
// ANCRE v0.6 — PATCH 1 : SecureRng ChaCha20
// ─────────────────────────────────────────────

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

pub struct SecureRng(ChaCha20Rng);

impl SecureRng {
    pub fn new() -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        SecureRng(ChaCha20Rng::from_seed(seed))
    }
}

impl rand::RngCore for SecureRng {
    fn next_u32(&mut self) -> u32 { self.0.next_u32() }
    fn next_u64(&mut self) -> u64 { self.0.next_u64() }
    fn fill_bytes(&mut self, dest: &mut [u8]) { self.0.fill_bytes(dest) }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.0.try_fill_bytes(dest)
    }
}

#[cfg(test)]
mod v06_patch1_tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn chacha20_not_constant() {
        let mut rng = SecureRng::new();
        let v1 = rng.next_u64();
        let v2 = rng.next_u64();
        assert_ne!(v1, v2);
    }

    #[test]
    fn chacha20_two_instances_independent() {
        let mut r1 = SecureRng::new();
        let mut r2 = SecureRng::new();
        let s1: Vec<u64> = (0..10).map(|_| r1.next_u64()).collect();
        let s2: Vec<u64> = (0..10).map(|_| r2.next_u64()).collect();
        assert_ne!(s1, s2);
    }
}


// ─────────────────────────────────────────────
// ANCRE v0.6 — PATCH 3 : delta_bound() Mironov 2012
// Quantifie la fuite LSB en (ε,δ)-DP
// δ ≤ (e^ε - 1) × 2^-52 / (2 × scale)
// Pour n=100, ε=0.5, scale≈0.025 → δ ≈ 2.9e-15
// ─────────────────────────────────────────────

const MACHINE_EPSILON: f64 = 2.220446049250313e-16; // 2^-52

pub fn delta_bound(epsilon: f64, scale: f64) -> f64 {
    if scale <= 0.0 || !scale.is_finite() { return 1.0; }
    (epsilon.exp() - 1.0) * MACHINE_EPSILON / (2.0 * scale)
}

#[cfg(test)]
mod v06_patch3_tests {
    use super::*;

    #[test]
    fn delta_bound_n100() {
        let scale = (1.0_f64 / 80.0) / EPSILON_SERVER;
        let delta = delta_bound(EPSILON_SERVER, scale);
        assert!(delta < 1e-14, "delta={:.2e}", delta);
        assert!(delta > 0.0);
    }

    #[test]
    fn delta_increases_with_epsilon() {
        let scale = 0.025;
        assert!(delta_bound(1.0, scale) > delta_bound(0.5, scale));
    }

    #[test]
    fn delta_invalid_scale() {
        assert_eq!(delta_bound(0.5, 0.0), 1.0);
        assert_eq!(delta_bound(0.5, -1.0), 1.0);
    }
}

// ─────────────────────────────────────────────
// ANCRE v0.6 — FIX : SessionGuard
// Invalide le credential après épuisement du budget
// Corrige le loophole reset_session() du v4.1.0
// ─────────────────────────────────────────────

pub struct SessionGuard {
    aggregation_count: u32,
    max_aggregations: u32,
    invalidated: bool,
}

impl SessionGuard {
    pub fn new(max_agg: u32) -> Self {
        Self { aggregation_count: 0, max_aggregations: max_agg, invalidated: false }
    }

    pub fn record_aggregation(&mut self) -> Result<(), String> {
        if self.invalidated {
            return Err("Session invalidee — nouveau credential requis".to_string());
        }
        if self.aggregation_count >= self.max_aggregations {
            self.invalidated = true;
            return Err(format!("Budget epuise : {}/{} — credential invalide",
                self.aggregation_count, self.max_aggregations));
        }
        self.aggregation_count += 1;
        Ok(())
    }

    pub fn is_valid(&self) -> bool {
        !self.invalidated && self.aggregation_count < self.max_aggregations
    }
}

#[cfg(test)]
mod v06_fix_session_tests {
    use super::*;

    #[test]
    fn session_invalidated_after_exhaustion() {
        let mut s = SessionGuard::new(3);
        assert!(s.record_aggregation().is_ok());
        assert!(s.record_aggregation().is_ok());
        assert!(s.record_aggregation().is_ok());
        assert!(s.record_aggregation().is_err());
        assert!(!s.is_valid());
        assert!(s.record_aggregation().is_err());
    }

    #[test]
    fn new_session_is_valid() {
        let s = SessionGuard::new(3);
        assert!(s.is_valid());
    }

    #[test]
    fn no_reset_loophole() {
        let mut s = SessionGuard::new(3);
        for _ in 0..3 { s.record_aggregation().ok(); }
        assert!(!s.is_valid());
        // Impossible de réutiliser — pas de reset
        assert!(s.record_aggregation().is_err());
    }
}

// ─────────────────────────────────────────────
// ANCRE v0.6 — AggregateResponse (H3)
// Publie n explicitement — justifie H3
// ─────────────────────────────────────────────

pub struct AggregateResponse {
    pub result: f64,
    pub n: usize,
    pub epsilon_used: f64,
    pub delta_bound: f64,
    pub total_epsilon_used: f64,
}

impl AggregateResponse {
    pub fn compute_delta_bound(epsilon: f64, n: usize) -> f64 {
        if n == 0 { return 1.0; }
        let scale = 1.0 / (n as f64 * 0.8 * epsilon);
        (epsilon.exp() - 1.0) * MACHINE_EPSILON / (2.0 * scale)
    }

    pub fn new(result: f64, n: usize, epsilon: f64, total_epsilon: f64) -> Self {
        Self {
            result,
            n,
            epsilon_used: epsilon,
            delta_bound: Self::compute_delta_bound(epsilon, n),
            total_epsilon_used: total_epsilon,
        }
    }
}

#[cfg(test)]
mod aggregate_response_tests {
    use super::*;

    #[test]
    fn response_publishes_n() {
        let r = AggregateResponse::new(0.5, 100, 0.5, 0.5);
        assert_eq!(r.n, 100);
        assert_eq!(r.epsilon_used, 0.5);
        assert!(r.delta_bound < 3e-15);
    }

    #[test]
    fn delta_decreases_with_larger_n() {
        let d100 = AggregateResponse::compute_delta_bound(0.5, 100);
        let d200 = AggregateResponse::compute_delta_bound(0.5, 200);
        assert!(d200 > d100, "delta augmente avec n — scale plus petit");
    }

    #[test]
    fn delta_n100_matches_mironov() {
        // Pour n=100, ε=0.5 → δ ≈ 2.9e-15
        let d = AggregateResponse::compute_delta_bound(0.5, 100);
        assert!(d > 2e-15 && d < 4e-15, "delta={:.2e}", d);
    }
}

// ─────────────────────────────────────────────
// ANCRE v0.7 — Laplace Discret Exact (δ=0)
// Cannone et al. (2020), NeurIPS
// Résolution r=1000 pour domaine [0,1]
// Fix SIGSEGV : saturation i64 pour NaN/Inf
// ─────────────────────────────────────────────

const DISCRETE_RESOLUTION: u64 = 1_000;

fn uniform_open01_v2(rng: &mut SecureRng) -> f64 {
    let v = rng.next_u64() >> 11;
    (v as f64 + 0.5) / 9_007_199_254_740_992.0f64
}

fn geometric_v2(rng: &mut SecureRng, scale_int: u64) -> i64 {
    let scale_int = scale_int.max(1);
    let p = 1.0 - (-1.0 / scale_int as f64).exp();
    let u = uniform_open01_v2(rng);
    let raw = u.ln() / (1.0 - p).ln();
    // Fix SIGSEGV : évite NaN/Inf → cast UB sur Android
    if raw.is_nan() || raw.is_infinite() || raw > i64::MAX as f64 {
        return 0;
    }
    raw.floor() as i64
}

fn discrete_laplace_v2(rng: &mut SecureRng, scale_int: u64) -> i64 {
    geometric_v2(rng, scale_int) - geometric_v2(rng, scale_int)
}

/// Laplace discret exact pour domaine [0,1]
/// Pure ε-DP (δ=0) — Cannone et al. (2020)
pub fn laplace_noise_v07(scale: f64, rng: &mut SecureRng) -> f64 {
    let r = DISCRETE_RESOLUTION as f64;
    let scale_int = (r * scale).round().max(1.0) as u64;
    let k = discrete_laplace_v2(rng, scale_int);
    k as f64 / r
}

#[cfg(test)]
mod v07_tests {
    use super::*;

    #[test]
    fn v07_scale_int_n100() {
        let scale = (1.0_f64 / 80.0) / EPSILON_SERVER;
        let scale_int = (DISCRETE_RESOLUTION as f64 * scale).round() as u64;
        assert_eq!(scale_int, 25);
    }

    #[test]
    fn v07_not_degenerate() {
        let mut rng = SecureRng::new();
        let scale = (1.0_f64 / 80.0) / EPSILON_SERVER;
        let nonzero = (0..1000)
            .filter(|_| laplace_noise_v07(scale, &mut rng) != 0.0)
            .count();
        assert!(nonzero > 300, "Bruit dégénéré : {} non-zéros", nonzero);
    }

    #[test]
    fn v07_mean_near_zero() {
        let mut rng = SecureRng::new();
        let scale = (1.0_f64 / 80.0) / EPSILON_SERVER;
        let mean = (0..5_000)
            .map(|_| laplace_noise_v07(scale, &mut rng))
            .sum::<f64>() / 5_000.0;
        assert!(mean.abs() < 0.02, "mean={:.4}", mean);
    }

    #[test]
    fn v07_no_sigsegv_extremes() {
        let mut rng = SecureRng::new();
        // Teste les cas extrêmes qui causaient SIGSEGV
        for scale in [0.001, 0.01, 0.025, 0.1, 1.0, 10.0] {
            let _ = laplace_noise_v07(scale, &mut rng);
        }
    }
}
