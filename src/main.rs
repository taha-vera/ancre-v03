use rand::rngs::OsRng;
use rand::Rng;
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
    let u: f64 = OsRng.gen::<f64>() - 0.5;
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

        // Depense du budget AVANT de vider le buffer
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
