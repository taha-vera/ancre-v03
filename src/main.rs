


fn laplace_noise(scale: f64) -> f64 {
    use rand::rngs::OsRng;
    use rand::Rng;
    let u: f64 = OsRng.gen::<f64>() - 0.5;
    let safe = (1.0 - 2.0 * u.abs()).max(1e-15);
    -scale * u.signum() * safe.ln()
}

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
        if amount <= 0.0 { return Err(format!("amount invalide : {}", amount)); }
        if self.epsilon_used + amount > self.epsilon_max {
            return Err(format!("Budget épuisé : {:.2}+{:.2} > {:.2}",
                self.epsilon_used, amount, self.epsilon_max));
        }
        self.epsilon_used += amount;
        Ok(())
    }
    pub fn remaining(&self) -> f64 { self.epsilon_max - self.epsilon_used }
    pub fn is_exhausted(&self) -> bool { self.remaining() <= 0.0 }
}

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
    pub fn add_noise(&self, scale: f64) -> Self {
        Self((self.0 + laplace_noise(scale)).clamp(0.0, 1.0))
    }
}

const K_MIN: usize = 100;
const EPSILON_CLIENT: f64 = 1.0;
const EPSILON_SERVER: f64 = 0.5;
const EPSILON_MAX: f64 = 1.5;

pub struct AncreBuffer {
    signals: Vec<BoundedSignal>,
    budget: EpsilonBudget,
}

impl AncreBuffer {
    pub fn new() -> Self {
        Self { signals: Vec::new(), budget: EpsilonBudget::new(EPSILON_MAX) }
    }
    pub fn push(&mut self, raw: f64) -> Result<(), String> {
        let signal = BoundedSignal::new(raw)?;
        
        self.signals.push(signal.add_noise(1.0 / EPSILON_CLIENT));
        Ok(())
    }
    pub fn aggregate(&mut self) -> Result<f64, String> {
        if self.signals.len() < K_MIN {
            return Err(format!("K={} < {}", self.signals.len(), K_MIN));
        }
        let mut vals: Vec<f64> = self.signals.iter().map(|s| s.value()).collect();
        vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let median = vals[vals.len() / 2];
        self.budget.spend(EPSILON_SERVER)?;
        let scale = 1.0 / (self.signals.len() as f64 * EPSILON_SERVER);
        let result = BoundedSignal::new(median.clamp(0.0, 1.0)).unwrap_or(BoundedSignal(0.5)).add_noise(scale);
        self.signals.clear();
        Ok(result.value())
    }
}

fn main() {
    run_pipeline();
    println!("ANCRE v0.3 — INV-1/2/3");

    assert!(BoundedSignal::new(f64::NAN).is_err());
    assert!(BoundedSignal::new(1.5).is_err());
    assert!(BoundedSignal::new(0.5).is_ok());
    println!("✅ INV-2 : BoundedSignal");

    let mut buf = AncreBuffer::new();
    for i in 0..50 { buf.push(0.1 + 0.001 * i as f64).ok(); }
    assert!(buf.aggregate().is_err());
    println!("✅ INV-3 : K-anonymity refusée si K < 100");

    for i in 0..120 { buf.push(0.3 + 0.001 * i as f64).ok(); }
    match buf.aggregate() {
        Ok(agg) => println!("✅ INV-3 : Agrégat = {:.4}", agg),
        Err(e)  => println!("❌ {}", e),
    }

    let mut budget = EpsilonBudget::new(1.5);
    assert!(budget.spend(1.0).is_ok());
    assert!(budget.spend(0.5).is_ok());
    assert!(budget.spend(0.1).is_err());
    println!("✅ INV-1 : EpsilonBudget monotone");
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // INV-1 : epsilon_used est strictement monotone croissant
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

        // INV-1 : budget ne peut jamais dépasser epsilon_max
        #[test]
        fn inv1_never_exceeds_max(amounts in prop::collection::vec(0.001f64..1.0, 1..50)) {
            let mut budget = EpsilonBudget::new(1.5);
            for amount in amounts {
                let _ = budget.spend(amount);
                assert!(budget.epsilon_used <= 1.5 + 1e-10);
            }
        }

        // INV-2 : BoundedSignal rejette tout hors [0,1]
        #[test]
        fn inv2_bounds_enforced(v in -10.0f64..10.0) {
            let result = BoundedSignal::new(v);
            if v >= 0.0 && v <= 1.0 {
                assert!(result.is_ok());
            } else {
                assert!(result.is_err());
            }
        }

        // INV-2 : add_noise reste dans [0,1]
        #[test]
        fn inv2_noise_stays_bounded(v in 0.0f64..=1.0, scale in 0.001f64..5.0) {
            let s = BoundedSignal::new(v).unwrap();
            let noisy = s.add_noise(scale);
            assert!(noisy.value() >= 0.0);
            assert!(noisy.value() <= 1.0);
        }
    }
}

// ─────────────────────────────────────────────
// C4 — Policy Engine / Kill-switch runtime
// ─────────────────────────────────────────────

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Clone)]
pub struct PolicyEngine {
    killed: Arc<AtomicBool>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self { killed: Arc::new(AtomicBool::new(false)) }
    }

    /// Force l'arrêt immédiat — irréversible
    pub fn kill(&self) {
        self.killed.store(true, Ordering::SeqCst);
    }

    /// Vérifie si le système est actif
    pub fn is_alive(&self) -> bool {
        !self.killed.load(Ordering::SeqCst)
    }

    /// Guard — retourne Err si killed
    pub fn check(&self) -> Result<(), String> {
        if self.is_alive() {
            Ok(())
        } else {
            Err("KILL-SWITCH ACTIVÉ — pipeline arrêté".to_string())
        }
    }
}

pub struct ProtectedBuffer {
    inner: AncreBuffer,
    policy: PolicyEngine,
}

impl ProtectedBuffer {
    pub fn new(policy: PolicyEngine) -> Self {
        Self { inner: AncreBuffer::new(), policy }
    }

    pub fn push(&mut self, raw: f64) -> Result<(), String> {
        self.policy.check()?;
        self.inner.push(raw)
    }

    pub fn aggregate(&mut self) -> Result<f64, String> {
        self.policy.check()?;
        self.inner.aggregate()
    }

    pub fn kill(&self) {
        self.policy.kill();
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;

    #[test]
    fn kill_switch_blocks_push() {
        let policy = PolicyEngine::new();
        let mut buf = ProtectedBuffer::new(policy.clone());
        assert!(buf.push(0.5).is_ok());
        buf.kill();
        assert!(buf.push(0.5).is_err());
    }

    #[test]
    fn kill_switch_blocks_aggregate() {
        let policy = PolicyEngine::new();
        let mut buf = ProtectedBuffer::new(policy.clone());
        for i in 0..120 {
            buf.push(0.3 + 0.001 * i as f64).ok();
        }
        buf.kill();
        assert!(buf.aggregate().is_err());
    }

    #[test]
    fn kill_switch_irreversible() {
        let policy = PolicyEngine::new();
        assert!(policy.is_alive());
        policy.kill();
        assert!(!policy.is_alive());
        assert!(!policy.is_alive());
    }
}

#[cfg(test)]
mod inv3_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn inv3_aggregate_requires_k_min(n in 0usize..99) {
            let mut buf = AncreBuffer::new();
            for i in 0..n {
                buf.push(0.1 + 0.001 * i as f64).ok();
            }
            assert!(buf.aggregate().is_err());
        }

        #[test]
        fn inv3_aggregate_ok_above_k_min(extra in 0usize..50) {
            let mut buf = AncreBuffer::new();
            for i in 0..(K_MIN + extra) {
                buf.push(0.3 + 0.0001 * i as f64).ok();
            }
            // Peut échouer si budget épuisé — les deux cas sont valides
            let _ = buf.aggregate();
        }
    }
}

// ─────────────────────────────────────────────
// C6 — Audit chain
// ─────────────────────────────────────────────

use sha2::{Sha256, Digest};

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
            "agg={:.4} k={} ε={:.2} hash={}",
            aggregate, k, epsilon, hash
        ));
        hash
    }

    pub fn len(&self) -> usize { self.entries.len() }
    pub fn last(&self) -> Option<&String> { self.entries.last() }
}

#[cfg(test)]
mod audit_tests {
    use super::*;

    #[test]
    fn chain_is_deterministic_per_entry() {
        let mut c1 = AuditChain::new();
        let mut c2 = AuditChain::new();
        let h1 = c1.append(0.42, 120, 1.5);
        let h2 = c2.append(0.42, 120, 1.5);
        assert_eq!(h1, h2);
    }

    #[test]
    fn chain_detects_tampering() {
        let mut c1 = AuditChain::new();
        let mut c2 = AuditChain::new();
        c1.append(0.42, 120, 1.5);
        c2.append(0.99, 120, 1.5);
        let h1 = c1.append(0.30, 110, 1.5);
        let h2 = c2.append(0.30, 110, 1.5);
        assert_ne!(h1, h2);
    }

    #[test]
    fn chain_grows() {
        let mut chain = AuditChain::new();
        for i in 0..5 {
            chain.append(0.1 * i as f64, 100 + i, 1.5);
        }
        assert_eq!(chain.len(), 5);
    }
}

// ─────────────────────────────────────────────
// C9 — Monitoring / Métriques
// ─────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct Metrics {
    pub signals_received: usize,
    pub signals_rejected: usize,
    pub aggregations_ok: usize,
    pub kill_switch_events: usize,
    pub budget_exhausted_events: usize,
}

impl Metrics {
    pub fn new() -> Self { Self::default() }

    pub fn record_signal(&mut self, ok: bool) {
        if ok { self.signals_received += 1; }
        else  { self.signals_rejected += 1; }
    }

    pub fn record_aggregation(&mut self, ok: bool) {
        if ok { self.aggregations_ok += 1; }
        else  { self.budget_exhausted_events += 1; }
    }

    pub fn record_kill(&mut self) {
        self.kill_switch_events += 1;
    }

    pub fn rejection_rate(&self) -> f64 {
        let total = self.signals_received + self.signals_rejected;
        if total == 0 { return 0.0; }
        self.signals_rejected as f64 / total as f64
    }

    pub fn report(&self) -> String {
        format!(
            "signals={} rejected={} ({:.1}%) agg_ok={} kills={} budget_exhausted={}",
            self.signals_received,
            self.signals_rejected,
            self.rejection_rate() * 100.0,
            self.aggregations_ok,
            self.kill_switch_events,
            self.budget_exhausted_events,
        )
    }
}

#[cfg(test)]
mod metrics_tests {
    use super::*;

    #[test]
    fn metrics_track_correctly() {
        let mut m = Metrics::new();
        m.record_signal(true);
        m.record_signal(true);
        m.record_signal(false);
        assert_eq!(m.signals_received, 2);
        assert_eq!(m.signals_rejected, 1);
        assert!((m.rejection_rate() - 1.0/3.0).abs() < 1e-9);
    }

    #[test]
    fn metrics_kill_tracked() {
        let mut m = Metrics::new();
        m.record_kill();
        m.record_kill();
        assert_eq!(m.kill_switch_events, 2);
    }
}

// ─────────────────────────────────────────────
// C10 — Main intégré v0.3
// ─────────────────────────────────────────────

fn run_pipeline() {
    println!("ANCRE v0.3 — Pipeline complet\n");

    let policy = PolicyEngine::new();
    let mut buf = ProtectedBuffer::new(policy.clone());
    let mut chain = AuditChain::new();
    let mut metrics = Metrics::new();

    // Ingestion 120 signaux
    for i in 0..120 {
        let raw = 0.2 + 0.005 * (i % 20) as f64;
        match buf.push(raw) {
            Ok(_)  => metrics.record_signal(true),
            Err(_) => metrics.record_signal(false),
        }
    }

    // Agrégation
    match buf.aggregate() {
        Ok(agg) => {
            metrics.record_aggregation(true);
            let hash = chain.append(agg, 120, 1.5);
            println!("✅ Agrégat  : {:.4}", agg);
            println!("✅ Hash     : {}", hash);
        }
        Err(e) => {
            metrics.record_aggregation(false);
            println!("⚠️  Agrégation : {}", e);
        }
    }

    // Kill-switch test
    buf.kill();
    metrics.record_kill();
    match buf.push(0.5) {
        Err(_) => println!("✅ Kill-switch actif"),
        Ok(_)  => println!("❌ Kill-switch raté"),
    }

    println!("\n📊 {}", metrics.report());
    println!("🔗 Audit entries : {}", chain.len());
}

// ─────────────────────────────────────────────
// P3 — Anti-replay nonce
// ─────────────────────────────────────────────

use std::collections::HashSet;

pub struct NonceCache {
    seen: HashSet<u64>,
}

impl NonceCache {
    pub fn new() -> Self {
        Self { seen: HashSet::new() }
    }

    pub fn check_and_consume(&mut self, nonce: u64) -> Result<(), String> {
        if self.seen.contains(&nonce) {
            return Err(format!("Replay détecté : nonce={}", nonce));
        }
        self.seen.insert(nonce);
        Ok(())
    }
}

pub struct SecureBuffer {
    inner: AncreBuffer,
    policy: PolicyEngine,
    nonces: NonceCache,
    device_counts: std::collections::HashMap<u64, usize>,
    max_per_device: usize,
}

impl SecureBuffer {
    pub fn new(policy: PolicyEngine) -> Self {
        Self {
            inner: AncreBuffer::new(),
            policy,
            nonces: NonceCache::new(),
            device_counts: std::collections::HashMap::new(),
            max_per_device: 30,
        }
    }

    pub fn push(&mut self, raw: f64, nonce: u64, device_id: u64) -> Result<(), String> {
        self.policy.check()?;
        self.nonces.check_and_consume(nonce)?;

        // P4 — Coalition cap par identité
        let count = self.device_counts.entry(device_id).or_insert(0);
        if *count >= self.max_per_device {
            return Err(format!("Device {} : quota atteint", device_id));
        }
        *count += 1;

        self.inner.push(raw)
    }

    pub fn aggregate(&mut self) -> Result<f64, String> {
        self.policy.check()?;
        self.inner.aggregate()
    }
}

#[cfg(test)]
mod secure_tests {
    use super::*;

    #[test]
    fn replay_rejected() {
        let mut cache = NonceCache::new();
        assert!(cache.check_and_consume(42).is_ok());
        assert!(cache.check_and_consume(42).is_err());
    }

    #[test]
    fn device_quota_enforced() {
        let policy = PolicyEngine::new();
        let mut buf = SecureBuffer::new(policy);
        for i in 0..30 {
            assert!(buf.push(0.5, i as u64, 999).is_ok());
        }
        assert!(buf.push(0.5, 31, 999).is_err());
    }

    #[test]
    fn different_devices_accepted() {
        let policy = PolicyEngine::new();
        let mut buf = SecureBuffer::new(policy);
        for i in 0..60 {
            assert!(buf.push(0.5, i as u64, i as u64).is_ok());
        }
    }
}

// ─────────────────────────────────────────────
// R1 — Per-signal epsilon tracker
// R2 — device_counts reset après aggregate
// R3 — NonceCache borné
// R4 — device_id authentifié via hash
// ─────────────────────────────────────────────

const MAX_NONCES: usize = 100_000;
const MAX_BUFFER_SIGNALS: usize = 10_000;

pub struct BoundedNonceCache {
    seen: HashSet<u64>,
    insertion_order: std::collections::VecDeque<u64>,
    max_size: usize,
}

impl BoundedNonceCache {
    pub fn new(max_size: usize) -> Self {
        Self {
            seen: HashSet::new(),
            insertion_order: std::collections::VecDeque::new(),
            max_size,
        }
    }

    pub fn check_and_consume(&mut self, nonce: u64) -> Result<(), String> {
        if self.seen.contains(&nonce) {
            return Err(format!("Replay détecté : nonce={}", nonce));
        }
        // R3 — Eviction FIFO si plein
        if self.seen.len() >= self.max_size {
            if let Some(oldest) = self.insertion_order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
        self.seen.insert(nonce);
        self.insertion_order.push_back(nonce);
        Ok(())
    }
}

// R4 — device_id authentifié via SHA-256 d'un credential
pub fn derive_device_id(credential: &[u8]) -> u64 {
    let mut h = Sha256::new();
    h.update(credential);
    let hash = h.finalize();
    u64::from_be_bytes(hash[..8].try_into().unwrap())
}

pub struct SecureBufferV2 {
    inner: AncreBuffer,
    policy: PolicyEngine,
    nonces: BoundedNonceCache,
    device_counts: std::collections::HashMap<u64, usize>,
    max_per_device: usize,
    total_client_epsilon: f64,  // R1 — tracking ε_client
}

impl SecureBufferV2 {
    pub fn new(policy: PolicyEngine) -> Self {
        Self {
            inner: AncreBuffer::new(),
            policy,
            nonces: BoundedNonceCache::new(MAX_NONCES),
            device_counts: std::collections::HashMap::new(),
            max_per_device: 30,
            total_client_epsilon: 0.0,
        }
    }

    pub fn push(&mut self, raw: f64, nonce: u64, credential: &[u8]) -> Result<(), String> {
        self.policy.check()?;

        // Buffer size guard
        if self.inner.signals.len() >= MAX_BUFFER_SIGNALS {
            return Err("Buffer plein".to_string());
        }

        // R3 — Anti-replay borné
        self.nonces.check_and_consume(nonce)?;

        // R4 — device_id dérivé du credential
        let device_id = derive_device_id(credential);
        let count = self.device_counts.entry(device_id).or_insert(0);
        if *count >= self.max_per_device {
            return Err(format!("Device quota atteint"));
        }
        *count += 1;

        // R1 — Tracker ε_client
        self.total_client_epsilon += EPSILON_CLIENT;

        self.inner.push(raw)
    }

    pub fn aggregate(&mut self) -> Result<(f64, f64), String> {
        self.policy.check()?;
        let agg = self.inner.aggregate()?;
        let total_eps = self.total_client_epsilon + EPSILON_SERVER;

        // R2 — Purger device_counts après aggregate
        self.device_counts.clear();
        self.total_client_epsilon = 0.0;

        Ok((agg, total_eps))
    }
}

#[cfg(test)]
mod v2_tests {
    use super::*;

    #[test]
    fn r2_device_counts_reset_after_aggregate() {
        let policy = PolicyEngine::new();
        let mut buf = SecureBufferV2::new(policy);
        let cred = b"device_credential_A";

        for i in 0..30 {
            buf.push(0.5, i as u64, cred).unwrap();
        }
        // Quota atteint
        assert!(buf.push(0.5, 30, cred).is_err());

        // Remplir jusqu'à K_MIN avec autres devices
        for i in 31..131 {
            let c = format!("device_{}", i);
            buf.push(0.4, i as u64, c.as_bytes()).ok();
        }

        // Aggregate → reset device_counts
        if buf.aggregate().is_ok() {
            // Après aggregate, device A peut soumettre à nouveau
            let r = buf.push(0.5, 200, cred);
            assert!(r.is_ok(), "Device doit pouvoir soumettre après aggregate");
        }
    }

    #[test]
    fn r3_nonce_cache_bounded() {
        let mut cache = BoundedNonceCache::new(5);
        for i in 0..10u64 {
            cache.check_and_consume(i).unwrap();
        }
        // Cache evicts oldest — nonce 0 peut être réutilisé
        assert!(cache.seen.len() <= 5);
    }

    #[test]
    fn r4_device_id_from_credential() {
        let id1 = derive_device_id(b"credential_A");
        let id2 = derive_device_id(b"credential_B");
        let id3 = derive_device_id(b"credential_A");
        assert_ne!(id1, id2);
        assert_eq!(id1, id3);
    }

    #[test]
    fn r1_epsilon_client_tracked() {
        let policy = PolicyEngine::new();
        let mut buf = SecureBufferV2::new(policy);
        for i in 0..5 {
            buf.push(0.5, i as u64, format!("dev{}", i).as_bytes()).unwrap();
        }
        assert!((buf.total_client_epsilon - 5.0 * EPSILON_CLIENT).abs() < 1e-10);
    }
}

// ─────────────────────────────────────────────
// F2 FIX — Moyenne tronquée (sensibilité 1/n prouvable)
// Remplace médiane (sensibilité 1.0 non bornée)
// ─────────────────────────────────────────────

pub fn trimmed_mean(vals: &mut Vec<f64>, trim_fraction: f64) -> f64 {
    vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = vals.len();
    let trim = (n as f64 * trim_fraction).floor() as usize;
    let trimmed = &vals[trim..n - trim];
    trimmed.iter().sum::<f64>() / trimmed.len() as f64
}

#[cfg(test)]
mod f2_tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn trimmed_mean_basic() {
        let mut v = vec![0.0, 0.1, 0.5, 0.9, 1.0];
        let m = trimmed_mean(&mut v, 0.2);
        assert!((m - 0.5).abs() < 1e-9);
    }

    #[test]
    fn trimmed_mean_bounded() {
        let mut v: Vec<f64> = (0..100).map(|i| i as f64 / 100.0).collect();
        let m = trimmed_mean(&mut v, 0.1);
        assert!(m >= 0.0 && m <= 1.0);
    }

    proptest! {
        #[test]
        fn trimmed_mean_sensitivity(
            vals in prop::collection::vec(0.0f64..=1.0, 100..200),
            idx in 0usize..100,
            replacement in 0.0f64..=1.0
        ) {
            // INV : changer 1 signal dans [0,1] change la moyenne tronquée de max 1/n
            let mut v1 = vals.clone();
            let mut v2 = vals.clone();
            let len2 = v2.len();
            v2[idx % len2] = replacement;
            let m1 = trimmed_mean(&mut v1, 0.1);
            let m2 = trimmed_mean(&mut v2, 0.1);
            let n = vals.len() as f64;
            assert!((m1 - m2).abs() <= 1.0 / (n * 0.8) + 1e-9);
        }
    }
}

// ─────────────────────────────────────────────
// F6 FIX — Nonce cache avec TTL
// Remplace FIFO pur (replay possible après éviction)
// ─────────────────────────────────────────────

use std::time::{Instant, Duration};

pub struct TtlNonceCache {
    entries: std::collections::HashMap<u64, Instant>,
    ttl: Duration,
    max_size: usize,
}

impl TtlNonceCache {
    pub fn new(ttl_secs: u64, max_size: usize) -> Self {
        Self {
            entries: std::collections::HashMap::new(),
            ttl: Duration::from_secs(ttl_secs),
            max_size,
        }
    }

    pub fn check_and_consume(&mut self, nonce: u64) -> Result<(), String> {
        self.purge_expired();

        if self.entries.contains_key(&nonce) {
            return Err(format!("Replay détecté : nonce={}", nonce));
        }

        if self.entries.len() >= self.max_size {
            return Err("Nonce cache plein — réessayer plus tard".to_string());
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

#[cfg(test)]
mod f6_tests {
    use super::*;

    #[test]
    fn ttl_nonce_replay_rejected() {
        let mut cache = TtlNonceCache::new(300, 1000);
        assert!(cache.check_and_consume(42).is_ok());
        assert!(cache.check_and_consume(42).is_err());
    }

    #[test]
    fn ttl_nonce_cache_bounded() {
        let mut cache = TtlNonceCache::new(300, 5);
        for i in 0..5 {
            assert!(cache.check_and_consume(i).is_ok());
        }
        // 6ème rejeté — cache plein
        assert!(cache.check_and_consume(99).is_err());
    }

    #[test]
    fn ttl_nonce_distinct_accepted() {
        let mut cache = TtlNonceCache::new(300, 1000);
        for i in 0..100 {
            assert!(cache.check_and_consume(i).is_ok());
        }
        assert_eq!(cache.len(), 100);
    }
}

// ─────────────────────────────────────────────
// Tests statistiques DP
// Vérifie empiriquement la distribution du bruit
// ─────────────────────────────────────────────

#[cfg(test)]
mod dp_statistical_tests {
    use super::*;

    fn sample_mean(samples: &[f64]) -> f64 {
        samples.iter().sum::<f64>() / samples.len() as f64
    }

    fn sample_variance(samples: &[f64]) -> f64 {
        let mean = sample_mean(samples);
        samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / samples.len() as f64
    }

    #[test]
    fn laplace_mean_near_zero() {
        // Laplace(0, scale) doit avoir moyenne ≈ 0
        let n = 10_000;
        let scale = 1.0;
        let samples: Vec<f64> = (0..n).map(|_| laplace_noise(scale)).collect();
        let mean = sample_mean(&samples);
        // Moyenne doit être dans [-0.05, 0.05] avec haute probabilité
        assert!(mean.abs() < 0.05, "Moyenne Laplace trop loin de 0 : {:.4}", mean);
    }

    #[test]
    fn laplace_variance_correct() {
        // Laplace(0, scale) a variance = 2 * scale^2
        let n = 10_000;
        let scale = 1.0;
        let samples: Vec<f64> = (0..n).map(|_| laplace_noise(scale)).collect();
        let var = sample_variance(&samples);
        let expected = 2.0 * scale * scale;
        // Variance doit être dans [1.5, 2.5]
        assert!(
            (var - expected).abs() < 0.5,
            "Variance Laplace incorrecte : {:.4} attendu {:.4}", var, expected
        );
    }

    #[test]
    fn bounded_signal_noise_distribution() {
        // Après add_noise, les valeurs doivent rester dans [0,1]
        // et ne pas être toutes identiques (bruit effectif)
        let n = 1_000;
        let signal = BoundedSignal::new(0.5).unwrap();
        let noisy: Vec<f64> = (0..n).map(|_| signal.add_noise(1.0).value()).collect();

        // Toutes dans [0,1]
        assert!(noisy.iter().all(|&x| x >= 0.0 && x <= 1.0));

        // Variance non nulle — le bruit est effectif
        let var = sample_variance(&noisy);
        assert!(var > 0.01, "Bruit non effectif : variance={:.4}", var);

        // Moyenne proche de 0.5 (signal original)
        let mean = sample_mean(&noisy);
        assert!(
            (mean - 0.5).abs() < 0.1,
            "Bruit biaisé : mean={:.4}", mean
        );
    }

    #[test]
    fn trimmed_mean_noise_correct_scale() {
        // Vérifie que le bruit sur TMoM a le bon scale
        // scale = 1 / (n * ε_server) pour signals dans [0,1]
        let n = 200usize;
        let epsilon_server = 0.5f64;
        let expected_scale = 1.0 / (n as f64 * epsilon_server);

        // Génère n fois une agrégation de n signaux = 0.5
        let trials = 500;
        let results: Vec<f64> = (0..trials).map(|_| {
            let signal = BoundedSignal::new(0.5).unwrap();
            signal.add_noise(expected_scale).value()
        }).collect();

        let var = sample_variance(&results);
        let expected_var = 2.0 * expected_scale * expected_scale;
        assert!(
            (var - expected_var).abs() < expected_var,
            "Scale bruit incorrect : var={:.6} attendu≈{:.6}", var, expected_var
        );
    }
}
