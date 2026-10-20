# ADR 0108: Optional BNRoSe diagnostic shadow

- **Status:** Proposed
- **Date:** 2026-10-19
- **Decision owners:** x0x maintainers and the receiving peer's operator
- **Supersedes:** none
- **Related:** security remediation PR #3; BNRoSe execution core

## Context

Evaluate a bounded intention kernel against actual x0x authentication work before
considering any execution integration. Peer autonomy and existing ML-DSA-65
verification must remain intact. This experiment depends on PR #3's fixes but
lives on a separate branch.

## Decision Drivers

- Preserve signed identity, transport, delivery and local refusal boundaries.
- Measure overhead honestly and retain raw paired measurements.
- Avoid unbounded queues, global coordination and additional signing authority.

## Considered Options

1. Insert a durable execution supervisor in gossip reception.
2. Add an optional, caller-owned diagnostic observer without production wiring.
3. Infer benefit from historical BNR microbenchmarks.

## Decision

Propose option 2. Feature `bnrose-shadow` is off by default. One `ShadowObserver`
belongs to one locally selected machine/agent binding. It accepts bounded X0A3/X0A4
bytes, calls the existing `IdentityAnnouncementV3::verify`, checks local scope and
signed freshness, and derives a zero-amount WB001 diagnostic envelope. The
receiving peer is the envelope authority; the source machine has signed only its
original announcement. The core verdict is unsigned local telemetry, never
remote consent, group membership, agent authorization, execution or settlement.

Each observer retains one timestamp/version watermark. Duplicate or older
observations refuse after signature verification; restarting an observer clears
this ephemeral watermark. There is no durable exactly-once claim. New policy
means a new observer. Disabled policy refuses without processing input.

The pinned Apache-2.0 BNR dependency closure is only `bnrose-exec-core`,
`btungsten-wb001-core` and the already-used SHA-256 dependency. No Ed25519 receipt
host, wallet, remote executor or background network task is introduced.

NixOS is the preferred Linux modality for synergy. `nix/shadow/flake.lock` pins
the shell packages; Rust remains explicitly 1.95.0 through rustup and Cargo.lock
pins dependencies. This is a development shell, not a hermetic Nix derivation or
a NixOS deployment module. WSL/Nix-shell results are labelled separately from
NixOS-host results.

## Consequences

### Positive

Peer-owned policy and bounded state can be examined without modifying packet
handling or giving the core effect authority. Existing x0x ML-DSA verification
remains the authentication boundary (`announce_v3.rs::IdentityAnnouncementV3::verify`).

### Negative / Trade-offs

Shadow processing adds CPU work. An 8 KiB input cap bounds wire size; decoding
and verification still allocate transiently. The core uses fixed stack buffers.
No throughput, security audit, consensus or end-to-end performance gain follows
from an offline benchmark. Untrusted input sampling/rate limiting belongs to a
future receiving integration; the experimental module is not wired into ingress.

### Neutral / Operational

No production defaults, transport cryptography, network bytes, invitation
provenance or delivery guarantees change. PR #3's independent invitation test
failure remains separate. Adoption requires human review of this Proposed ADR.

## Validation

Offline negative controls cover tampering, classical-signature substitution,
wrong peer, stale/future timestamps, malformed/oversized bytes, trailing bytes,
local opt-out, replay and independent observers. The same real x0x verification
function is used by baseline and shadow, with signing outside timing regions.
Paired alternating-order samples retain per-operation nanoseconds and report
p50/p95/p99; 1/2/4 local observers measure same-process concurrency, not network
scale. Record toolchain, OS, exact revision, mode and raw output. Measure live
delivery, process memory, durable fsync, partitions and queue fairness separately
before any broader adoption claim.

The adapter uses the pinned WB001 `offsets` and `byte_at` functions to encode
only the transmitted prefix, with the remaining buffer explicitly zeroed.
For the fixed observation shape this visits 335 bytes instead of 4,626. The
core decoder, admission policy, signature verification and replay checks are
unchanged. An equivalence test compares the entire buffer to the original
encoder over all 4,097 payload lengths, text boundaries and integer edges
that fit the buffer; larger combined envelopes explicitly refuse. Individual
WB001 field-capacity checks alone do not guarantee a combined envelope fits.
This optimization does not cache authentication or add per-peer state.

