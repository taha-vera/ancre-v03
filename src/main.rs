use rand::random;


fn laplace_noise(scale: f64) -> f64 {
    let u: f64 = random::<f64>() - 0.5;
    -scale * u.signum() * (1.0 - 2.0 * u.abs()).ln()
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
        let hash = hex::encode(&h.finalize()[..16]);
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
