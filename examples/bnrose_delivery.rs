//! Isolated direct x0x transport experiment, not an ANT/WebRTC or gossip benchmark.
//! Requires the supplied Linux private-network launcher. Never joins public peers.
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::Mutex, task::JoinSet, time::timeout};
use x0x::{
    announce_v3::{deserialize_v3, serialize_v3_1, IdentityAnnouncementV3},
    bnrose_shadow::{verify_baseline, LocalPolicy, ShadowObserver, Verdict},
    identity::{AgentKeypair, MachineKeypair},
    network::{NetworkConfig, NetworkNode},
};

const PER_PHASE: usize = 128;
const PHASES: usize = 3;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn fixture(machine: &MachineKeypair, agent: &AgentKeypair) -> Vec<Vec<u8>> {
    (0..PER_PHASE * PHASES)
        .map(|id| {
            let mut a = IdentityAnnouncementV3 {
                agent_id: agent.agent_id(),
                machine_id: machine.machine_id(),
                agent_public_key: agent.public_key().as_bytes().to_vec(),
                machine_public_key: machine.public_key().as_bytes().to_vec(),
                addresses: vec![],
                announced_at: now(),
                nat_type: None,
                can_receive_direct: Some(true),
                is_relay: Some(false),
                is_coordinator: Some(false),
                reachable_via: vec![],
                relay_candidates: vec![],
                cert_digest: [0; 32],
                payload_version: id as u64,
                machine_signature: vec![],
                self_name: Some("isolated-delivery".into()),
                v31_signed: false,
            };
            a.sign_v3_1(machine.secret_key()).unwrap();
            serialize_v3_1(&a).unwrap()
        })
        .collect()
}

async fn node(key: &MachineKeypair, allowed: &MachineKeypair) -> Result<Arc<NetworkNode>> {
    let config = NetworkConfig {
        bind_addr: Some("127.0.0.1:0".parse()?),
        bootstrap_nodes: vec![],
        mdns_enabled: false,
        port_mapping_enabled: false,
        inbound_allowlist: HashSet::from([allowed.machine_id().0]),
        max_connections: 2,
        max_peers_per_ip: 2,
        ..NetworkConfig::default()
    };
    Ok(Arc::new(
        NetworkNode::new(
            config,
            None,
            Some((key.public_key().clone(), key.secret_key().clone())),
        )
        .await?,
    ))
}

async fn connect(a: &NetworkNode, b: &NetworkNode) -> Result<()> {
    let addr = b.bound_addr().await.context("receiver address")?;
    let peer = timeout(Duration::from_secs(10), a.connect_addr(addr)).await??;
    ensure!(peer == b.peer_id(), "unexpected transport identity");
    timeout(Duration::from_secs(10), a.ensure_peer_send_ready(&peer)).await??;
    Ok(())
}

fn collector(
    receiver: Arc<NetworkNode>,
    policy: LocalPolicy,
    shadow: bool,
    start: Instant,
    deliveries: Arc<Mutex<Vec<Value>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut observer = ShadowObserver::new(policy);
        while let Some((peer, framed)) = receiver.recv_direct().await {
            let received_us = start.elapsed().as_micros() as u64;
            if framed.len() < 32 || peer.0 != policy.machine.0 || framed[..32] != policy.agent.0 {
                deliveries
                    .lock()
                    .await
                    .push(json!({"error":"transport_binding"}));
                continue;
            }
            let wire = &framed[32..];
            let verification_start = Instant::now();
            let verdict = if shadow {
                observer.observe(wire, now())
            } else {
                match verify_baseline(wire, &policy, now()) {
                    Ok(_) => Verdict::Observed,
                    Err(v) => v,
                }
            };
            let verification_ns = verification_start.elapsed().as_nanos() as u64;
            // Replay is diagnostic only: it never withdraws already verified delivery.
            let accepted = matches!(verdict, Verdict::Observed | Verdict::Replay);
            let id = deserialize_v3(wire).ok().map(|a| a.payload_version);
            deliveries.lock().await.push(json!({
                "id": id, "accepted":accepted, "verdict":format!("{verdict:?}"),
                "received_us":received_us,
                "verified_us":start.elapsed().as_micros() as u64,
                "verification_ns":verification_ns, "wire_bytes":wire.len(),
            }));
        }
    })
}

async fn pair(pair_id: usize, window: usize, shadow: bool, churn: bool) -> Result<Value> {
    let sender_key = MachineKeypair::generate()?;
    let receiver_key = MachineKeypair::generate()?;
    let agent = AgentKeypair::generate()?;
    let wires = Arc::new(fixture(&sender_key, &agent));
    let sender = node(&sender_key, &receiver_key).await?;
    let mut receiver = node(&receiver_key, &sender_key).await?;
    connect(&sender, &receiver).await?;
    let policy = LocalPolicy {
        enabled: true,
        receiver: receiver_key.machine_id(),
        machine: sender_key.machine_id(),
        agent: agent.agent_id(),
        max_age_secs: 900,
    };
    let start = Instant::now();
    let deliveries = Arc::new(Mutex::new(Vec::new()));
    let mut reader = collector(receiver.clone(), policy, shadow, start, deliveries.clone());
    let mut sends = Vec::new();
    let mut lifecycle = Vec::new();
    let mut transport = Vec::new();
    for phase in 0..PHASES {
        if churn && phase == 1 {
            transport.push(json!({"phase":"before_shutdown",
                "stats":format!("{:?}", sender.connection_transport_stats(receiver.peer_id()).await)}));
            // Receiver exercises local withdrawal. Other peer pair remains loaded.
            receiver.try_shutdown().await?;
            reader.abort();
            lifecycle.push(json!({"event":"receiver_down","at_us":start.elapsed().as_micros()}));
        }
        if churn && phase == 2 {
            receiver = node(&receiver_key, &sender_key).await?;
            reader = collector(receiver.clone(), policy, shadow, start, deliveries.clone());
            let reconnect_start = Instant::now();
            connect(&sender, &receiver).await?;
            lifecycle.push(json!({"event":"receiver_rejoined",
                "at_us":start.elapsed().as_micros(),
                "connect_us":reconnect_start.elapsed().as_micros()}));
        }
        let mut tasks = JoinSet::new();
        for id in phase * PER_PHASE..(phase + 1) * PER_PHASE {
            if tasks.len() >= window {
                sends.push(tasks.join_next().await.context("missing send task")??);
            }
            let sender = sender.clone();
            let wires = wires.clone();
            let agent_id = agent.agent_id();
            let receiver_id = receiver.peer_id();
            tasks.spawn(async move {
                let sent_us = start.elapsed().as_micros() as u64;
                let result = timeout(
                    Duration::from_millis(500),
                    sender.send_direct(&receiver_id, agent_id.as_bytes(), &wires[id]),
                )
                .await;
                json!({"id":id,"phase":phase,"sent_us":sent_us,
                "finished_us":start.elapsed().as_micros() as u64,
                "send_ok":matches!(result, Ok(Ok(()))),
                "send_error":match result {
                    Ok(Ok(())) => None,
                    Ok(Err(e)) => Some(e.to_string()),
                    Err(_) => Some("benchmark send deadline 500ms".into()),
                }})
            });
        }
        while let Some(result) = tasks.join_next().await {
            sends.push(result?);
        }
        // Same bounded settle interval in both arms. Missing delivery stays missing.
        tokio::time::sleep(Duration::from_millis(500)).await;
        transport.push(json!({"phase":phase,
            "stats":format!("{:?}", sender.connection_transport_stats(receiver.peer_id()).await)}));
    }
    let measured_us = start.elapsed().as_micros();
    // Network-delivered signature negative control; signed bytes are modified.
    let mut invalid = deserialize_v3(&wires[0])?;
    invalid.payload_version = 999_999;
    let invalid = serialize_v3_1(&invalid)?;
    sender
        .send_direct(&receiver.peer_id(), agent.agent_id().as_bytes(), &invalid)
        .await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let rows = deliveries.lock().await.clone();
    ensure!(
        rows.iter()
            .any(|r| r["id"] == 999_999 && r["verdict"] == "Signature" && r["accepted"] == false),
        "tampered signature was not rejected on receive"
    );
    ensure!(
        !rows.iter().any(|r| r.get("error").is_some()),
        "unexpected transport binding"
    );
    reader.abort();
    sender.try_shutdown().await?;
    receiver.try_shutdown().await?;
    Ok(
        json!({"pair":pair_id,"shadow":shadow,"churn":churn,"window":window,
        "measured_us":measured_us,"wire_bytes":wires[0].len(),
        "sends":sends,"deliveries":rows,"lifecycle":lifecycle,"transport":transport}),
    )
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    ensure!(cfg!(target_os = "linux"), "Linux isolation required");
    ensure!(
        std::env::var("BNROSE_ISOLATED").as_deref() == Ok("1"),
        "use the isolation launcher"
    );
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 4,
        "usage: bnrose_delivery baseline|shadow 8|64 steady|churn"
    );
    ensure!(
        matches!(args[1].as_str(), "baseline" | "shadow"),
        "invalid arm"
    );
    ensure!(
        matches!(args[3].as_str(), "steady" | "churn"),
        "invalid churn"
    );
    let window = args[2].parse::<usize>()?;
    ensure!([8, 64].contains(&window), "unsupported bounded window");
    let shadow = args[1] == "shadow";
    let churn = args[3] == "churn";
    let (a, b) = tokio::try_join!(
        pair(0, window, shadow, churn),
        pair(1, window, shadow, false)
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema":"x0x.bnrose.direct-delivery.v1", "shadow":shadow,
            "window":window,"churn":churn,"pairs":[a,b],
            "transport":"x0x NetworkNode direct streams over pinned ant-quic; loopback private namespace",
            "limitations":"same-host two pairs; no WebRTC/ANT, WAN, gossip, DAO voting, quantum hardware or global capacity claim; no application retransmission",
        }))?
    );
    Ok(())
}
