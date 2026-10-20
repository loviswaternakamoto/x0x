//! Opt-in, in-process diagnostic shadow of verified x0x announcements.
//!
//! No network, keys, effects, journal, background task or execution capability.
//! A verdict is local telemetry, never delegated authority or a signed receipt.
//! Production receive paths do not call this experimental module.

use crate::{
    announce_v3,
    identity::{AgentId, MachineId},
};
use bnrose_exec_core::{admit, Policy, MAX_VERDICT};
use btungsten_wb001_core::{byte_at, offsets, Intent, MAX_ENV};
use sha2::{Digest, Sha256};

/// Maximum signed input accepted before decoding or signature verification.
pub const WIRE_CAP: usize = 8192;
const DOMAIN: &[u8] = b"x0x/shadow/v1";
const CAPABILITY: &[u8] = b"diagnostic/observe";

// Use the pinned core's byte definition only for the transmitted prefix.
// The original encoder also visits the zero padding up to MAX_ENV. Keeping
// that padding zero here avoids thousands of redundant block dispatches.
// This is private: callers below construct bounded, fixed-shape intents.
fn encode_observation(intent: &Intent, out: &mut [u8; MAX_ENV]) -> Option<usize> {
    let layout = offsets(intent);
    let len = layout.env as usize;
    out.fill(0);
    for (k, byte) in out.get_mut(..len)?.iter_mut().enumerate() {
        *byte = byte_at(intent, &layout, k as u32);
    }
    Some(len)
}

/// Receiver-owned scope. Every observer handles exactly one local peer binding.
#[derive(Clone, Copy)]
pub struct LocalPolicy {
    /// Explicit opt-in; disabled observers do no signature work.
    pub enabled: bool,
    /// Receiver's own machine; binds diagnostics to this observer.
    pub receiver: MachineId,
    /// Expected remote machine, selected locally (not from the input).
    pub machine: MachineId,
    /// Expected remote agent, selected locally (not from the input).
    pub agent: AgentId,
    /// Inclusive freshness window in seconds, capped at 900.
    pub max_age_secs: u64,
}

/// Local telemetry only. No variant authorizes an external effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Receiver opted out.
    Disabled,
    /// Invalid receiver configuration.
    Policy,
    /// Oversized or malformed announcement.
    Encoding,
    /// Existing x0x ML-DSA verification refused.
    Signature,
    /// Signed identity is outside the local peer binding.
    Scope,
    /// Signed timestamp is stale or in the future.
    Freshness,
    /// Same or older timestamp/version pair for this observer.
    Replay,
    /// BNRoSe core refused the diagnostic envelope.
    Core,
    /// Core admitted a local diagnostic observation, not execution.
    Observed,
}

/// Baseline: existing x0x decoding and ML-DSA verification with local scope/time.
/// No signature cache or alternate algorithm is accepted.
pub fn verify_baseline(
    wire: &[u8],
    policy: &LocalPolicy,
    now: u64,
) -> Result<announce_v3::IdentityAnnouncementV3, Verdict> {
    if !policy.enabled {
        return Err(Verdict::Disabled);
    }
    if policy.max_age_secs == 0 || policy.max_age_secs > 900 {
        return Err(Verdict::Policy);
    }
    if wire.len() > WIRE_CAP {
        return Err(Verdict::Encoding);
    }
    let announcement = announce_v3::deserialize_v3(wire).map_err(|_| Verdict::Encoding)?;
    announcement.verify().map_err(|_| Verdict::Signature)?;
    if announcement.machine_id != policy.machine || announcement.agent_id != policy.agent {
        return Err(Verdict::Scope);
    }
    if announcement.announced_at > now || now - announcement.announced_at > policy.max_age_secs {
        return Err(Verdict::Freshness);
    }
    Ok(announcement)
}

/// Constant-size state, owned exclusively by one receiving peer.
/// Replay bookkeeping is ephemeral and has no durable execution semantics.
pub struct ShadowObserver {
    policy: LocalPolicy,
    last: Option<(u64, u64)>,
}

impl ShadowObserver {
    /// Construct an observer from receiver-owned policy; opens no resources.
    pub fn new(policy: LocalPolicy) -> Self {
        Self { policy, last: None }
    }

    /// Observe synchronously. The caller decides whether/when to sample inputs.
    /// All input verification is identical to `verify_baseline`; no fast-path
    /// signature bypass exists, even for duplicates.
    pub fn observe(&mut self, wire: &[u8], now: u64) -> Verdict {
        let a = match verify_baseline(wire, &self.policy, now) {
            Ok(a) => a,
            Err(v) => return v,
        };
        let sequence = (a.announced_at, a.payload_version);
        if self.last.is_some_and(|last| sequence <= last) {
            return Verdict::Replay;
        }
        let digest: [u8; 32] = Sha256::digest(wire).into();
        let mut intent = Intent::ZERO;
        intent.domain[..DOMAIN.len()].copy_from_slice(DOMAIN);
        intent.domain_len = DOMAIN.len() as u32;
        intent.capability[..CAPABILITY.len()].copy_from_slice(CAPABILITY);
        intent.capability_len = CAPABILITY.len() as u32;
        intent.nonce = digest;
        intent.nonce_len = 32;
        intent.action = Sha256::digest(b"x0x/shadow/observe-announcement/v1").into();
        intent.action_len = 32;
        // Text fields use lowercase hex, never lossy decoding of identity bytes.
        let receiver = hex::encode(self.policy.receiver.as_bytes());
        intent.destination[..receiver.len()].copy_from_slice(receiver.as_bytes());
        intent.destination_len = receiver.len() as u32;
        let source = hex::encode(a.machine_id.as_bytes());
        intent.payer[..source.len()].copy_from_slice(source.as_bytes());
        intent.payer_len = source.len() as u32;
        intent.epoch = a.announced_at;
        intent.expiry = a.announced_at.saturating_add(self.policy.max_age_secs);
        intent.payload[..32].copy_from_slice(&digest);
        intent.payload_len = 32;
        // Amount remains zero. The core gets a digest-bound local observation;
        // the remote signature is NOT represented as signing this new envelope.
        let mut env = [0; MAX_ENV];
        let Some(len) = encode_observation(&intent, &mut env) else {
            return Verdict::Core;
        };
        let mut policy = Policy {
            domains: [([0; 64], 0); 4],
            capabilities: [([0; 64], 0); 4],
            max_amount: 0,
            min_lead: 0,
            max_payload: 32,
        };
        policy.domains[0].0[..DOMAIN.len()].copy_from_slice(DOMAIN);
        policy.domains[0].1 = DOMAIN.len() as u32;
        policy.capabilities[0].0[..CAPABILITY.len()].copy_from_slice(CAPABILITY);
        policy.capabilities[0].1 = CAPABILITY.len() as u32;
        let mut out = [0; MAX_VERDICT];
        if admit(
            self.policy.receiver.as_bytes(),
            &env[..len],
            &policy,
            now,
            &mut out,
        ) != Ok(97)
            || out[0] != 1
        {
            return Verdict::Core;
        }
        self.last = Some(sequence);
        Verdict::Observed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_encoder_matches_pinned_encoder_including_padding() {
        // Sweep every payload length plus text boundaries and integer edges;
        // compare the entire buffer, including reuse of nonzero scratch space.
        for payload_len in 0..=4096 {
            let mut intent = Intent::ZERO;
            let text_len = [1, 12, 17, 32, 63, 64][payload_len % 6];
            intent.domain[..text_len].fill(b'd');
            intent.domain_len = text_len as u32;
            intent.capability[..text_len].fill(b'c');
            intent.capability_len = text_len as u32;
            let identity_len = [1, 64, 127, 128][payload_len % 4];
            intent.destination[..identity_len].fill(b'7');
            intent.destination_len = identity_len as u32;
            intent.payer[..identity_len].fill(b'a');
            intent.payer_len = identity_len as u32;
            intent.nonce = [payload_len as u8; 32];
            intent.nonce_len = 32;
            intent.action = [!payload_len as u8; 32];
            intent.action_len = 32;
            intent.epoch = [0, 1, u32::MAX as u64, u64::MAX][payload_len % 4];
            intent.expiry = intent.epoch.saturating_add(900);
            intent.payload[..payload_len].fill(payload_len as u8);
            intent.payload_len = payload_len as u32;
            assert!(btungsten_wb001_core::valid_intent(&intent));
            let mut reference = [0xa5; MAX_ENV];
            let expected = btungsten_wb001_core::encode(&intent, &mut reference);
            let mut actual = [0x5a; MAX_ENV];
            let encoded = encode_observation(&intent, &mut actual);
            if expected as usize > MAX_ENV {
                // valid_intent checks field capacities, which do not imply
                // their combined wire fits MAX_ENV. Refuse without slicing.
                assert_eq!(encoded, None);
            } else {
                assert_eq!(encoded, Some(expected as usize));
                assert_eq!(actual, reference, "payload length {payload_len}");
            }
        }
    }
}
