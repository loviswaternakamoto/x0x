//! Offline paired measurement and negative controls. No sockets or key files.
use std::{hint::black_box, time::Instant};
use x0x::{
    announce_v3::{serialize_v3_1, IdentityAnnouncementV3},
    bnrose_shadow::{verify_baseline, LocalPolicy, ShadowObserver, Verdict},
    identity::{AgentKeypair, MachineId, MachineKeypair},
};

const NOW: u64 = 1_792_368_000;

fn fixture(count: usize) -> (Vec<Vec<u8>>, LocalPolicy) {
    let agent = AgentKeypair::generate().expect("ephemeral fixture agent");
    let machine = MachineKeypair::generate().expect("ephemeral fixture machine");
    let policy = LocalPolicy {
        enabled: true,
        receiver: MachineId([7; 32]),
        machine: machine.machine_id(),
        agent: agent.agent_id(),
        max_age_secs: 60,
    };
    let wires = (0..count)
        .map(|version| {
            let mut a = IdentityAnnouncementV3 {
                agent_id: agent.agent_id(),
                machine_id: machine.machine_id(),
                agent_public_key: agent.public_key().as_bytes().to_vec(),
                machine_public_key: machine.public_key().as_bytes().to_vec(),
                addresses: vec![],
                announced_at: NOW,
                nat_type: None,
                can_receive_direct: Some(false),
                is_relay: Some(false),
                is_coordinator: Some(false),
                reachable_via: vec![],
                relay_candidates: vec![],
                cert_digest: [0; 32],
                payload_version: version as u64,
                machine_signature: vec![],
                self_name: Some("offline-shadow-fixture".into()),
                v31_signed: false,
            };
            a.sign_v3_1(machine.secret_key()).unwrap();
            serialize_v3_1(&a).unwrap()
        })
        .collect();
    (wires, policy)
}

fn sample(wires: &[Vec<u8>], policy: LocalPolicy, shadow: bool) -> Vec<u64> {
    let mut observer = ShadowObserver::new(policy);
    wires
        .iter()
        .map(|wire| {
            let start = Instant::now();
            if shadow {
                assert_eq!(
                    black_box(observer.observe(black_box(wire), NOW)),
                    Verdict::Observed
                );
            } else {
                black_box(verify_baseline(black_box(wire), &policy, NOW).unwrap());
            }
            start.elapsed().as_nanos() as u64
        })
        .collect()
}

fn summary(mut times: Vec<u64>) -> serde_json::Value {
    times.sort_unstable();
    let n = times.len();
    serde_json::json!({"count":n,"p50_ns":times[n/2],"p95_ns":times[n*95/100],
        "p99_ns":times[n*99/100],"mean_ns":times.iter().sum::<u64>() as f64/n as f64})
}

fn main() {
    let (wires, policy) = fixture(64);
    // Warm both paths; fixture generation/signing are outside measured regions.
    for _ in 0..4 {
        sample(&wires, policy, false);
        sample(&wires, policy, true);
    }
    let mut baseline = Vec::new();
    let mut shadow = Vec::new();
    let mut pairs = Vec::new();
    for round in 0..32 {
        // Alternate ordering to reduce thermal/cache/order bias.
        let (b, s) = if round % 2 == 0 {
            (sample(&wires, policy, false), sample(&wires, policy, true))
        } else {
            let s = sample(&wires, policy, true);
            (sample(&wires, policy, false), s)
        };
        pairs.push(serde_json::json!({"round":round,"baseline_ns":b,"shadow_ns":s}));
        baseline.extend(b);
        shadow.extend(s);
    }
    let mut scaling = Vec::new();
    for peers in [1, 2, 4] {
        for shadow_on in [false, true] {
            let start = Instant::now();
            std::thread::scope(|scope| {
                for peer in 0..peers {
                    let wires = &wires;
                    scope.spawn(move || {
                        let mut local = policy;
                        local.receiver = MachineId([peer as u8; 32]);
                        for _ in 0..16 {
                            sample(wires, local, shadow_on);
                        }
                    });
                }
            });
            let elapsed = start.elapsed().as_secs_f64();
            scaling.push(
                serde_json::json!({"local_observers":peers,"shadow":shadow_on,
                "operations":peers*16*64,"elapsed_secs":elapsed,
                "operations_per_sec":(peers*16*64) as f64/elapsed}),
            );
        }
    }
    println!("{}", serde_json::to_string_pretty(&serde_json::json!({
        "schema":"x0x.bnrose-shadow.offline.v1","debug_assertions":cfg!(debug_assertions),
        "wire_bytes":wires[0].len(),"observer_bytes":std::mem::size_of::<ShadowObserver>(),
        "network_bytes_sent":0,"journal_fsyncs":0,"queue":"none; synchronous caller-owned sampling",
        "baseline":summary(baseline),"shadow":summary(shadow),"scaling":scaling,"pairs":pairs,
        "limitations":"offline receive verification only; no mesh delivery, durable execution, CPU isolation or production throughput claim"
    })).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;
    use x0x::announce_v3::deserialize_v3;

    #[test]
    fn verified_observation_is_local_and_replay_bounded() {
        let (w, p) = fixture(2);
        let mut a = ShadowObserver::new(p);
        let mut b = ShadowObserver::new(p);
        assert_eq!(a.observe(&w[0], NOW), Verdict::Observed);
        assert_eq!(a.observe(&w[0], NOW), Verdict::Replay);
        assert_eq!(b.observe(&w[0], NOW), Verdict::Observed);
        assert_eq!(a.observe(&w[1], NOW), Verdict::Observed);
        assert_eq!(a.observe(&w[0], NOW), Verdict::Replay);
        assert!(std::mem::size_of::<ShadowObserver>() < 256);
    }

    #[test]
    fn opt_out_and_invalid_local_policy_refuse() {
        let (w, mut p) = fixture(1);
        p.enabled = false;
        assert_eq!(
            ShadowObserver::new(p).observe(&w[0], NOW),
            Verdict::Disabled
        );
        p.enabled = true;
        for age in [0, 901, u64::MAX] {
            p.max_age_secs = age;
            assert_eq!(ShadowObserver::new(p).observe(&w[0], NOW), Verdict::Policy);
        }
    }

    #[test]
    fn scope_and_signed_freshness_refuse_without_poisoning_state() {
        let (w, p) = fixture(1);
        let mut wrong = p;
        wrong.agent = x0x::identity::AgentId([1; 32]);
        assert_eq!(
            ShadowObserver::new(wrong).observe(&w[0], NOW),
            Verdict::Scope
        );
        wrong = p;
        wrong.machine = MachineId([1; 32]);
        assert_eq!(
            ShadowObserver::new(wrong).observe(&w[0], NOW),
            Verdict::Scope
        );
        let mut o = ShadowObserver::new(p);
        assert_eq!(o.observe(&w[0], NOW - 1), Verdict::Freshness);
        assert_eq!(o.observe(&w[0], NOW + 61), Verdict::Freshness);
        assert_eq!(o.observe(&w[0], NOW + 60), Verdict::Observed);
    }

    #[test]
    fn tampering_and_classical_signature_substitution_refuse() {
        let (w, p) = fixture(1);
        for mutation in 0..5 {
            let mut a = deserialize_v3(&w[0]).unwrap();
            match mutation {
                0 => a.announced_at += 1,
                1 => a.self_name = Some("forged".into()),
                2 => a.machine_signature = vec![0; 64], // Ed25519-size substitution
                3 => a.machine_signature[0] ^= 1,
                _ => a.agent_public_key[0] ^= 1,
            }
            let bad = serialize_v3_1(&a).unwrap();
            let mut o = ShadowObserver::new(p);
            assert_eq!(o.observe(&bad, NOW), Verdict::Signature);
            assert_eq!(o.observe(&w[0], NOW), Verdict::Observed);
        }
    }

    #[test]
    fn malformed_oversized_and_trailing_wire_refuse() {
        let (w, p) = fixture(1);
        let mut trailing = w[0].clone();
        trailing.push(0);
        for bad in [vec![], vec![0; 8193], w[0][..100].to_vec(), trailing] {
            assert_eq!(ShadowObserver::new(p).observe(&bad, NOW), Verdict::Encoding);
        }
    }

    #[test]
    fn baseline_and_shadow_share_authentication_boundary() {
        let (w, p) = fixture(1);
        for i in (0..w[0].len()).step_by(97) {
            let mut bad = w[0].clone();
            bad[i] ^= 128;
            if let Err(expected) = verify_baseline(&bad, &p, NOW) {
                assert_eq!(ShadowObserver::new(p).observe(&bad, NOW), expected);
            } else {
                panic!("mutated signed wire accepted at {i}");
            }
        }
    }
}
