# BNRoSe shadow adapter — 2026-10-19

Separate experimental branch `codex/bnrose-shadow`, based on security PR #3 head
`8aaf9357c76aa4b9762ba253a3128b91e063bb16`. BNR core revision
`49b88d7b294687711b9871f34a74b961f7d5f62a` is pinned in Cargo.toml/Cargo.lock.

Implements an optional, receiver-owned diagnostic observer, with no production
receive-path wiring. See Proposed ADR 0108. Goal served: bounded local maintenance
diagnostics (R12 proposal); this is a fork experiment, not an accepted upstream
architecture change. It does not implement a maintenance agent or change x0x's
transport role.

## Reproduce (preferred NixOS Linux environment)

From this checkout:

```sh
nix develop path:./nix/shadow
rustup toolchain install 1.95.0 --profile minimal --component rustfmt,clippy
CARGO_TARGET_DIR=/tmp/x0x-shadow-target bash scripts/dev/bench-bnrose-shadow.sh /tmp/x0x-shadow-receipt
```

Use a new receipt directory per run. Rust dependencies are locked; the Nix shell
pins system build tools. Rustup downloads the explicitly named toolchain, so this
is not a hermetic derivation. The script runs only the reviewed inert example
tests and offline benchmark. It never starts x0xd or accesses an identity store.
Process accounting uses the shell's GNU `time` executable, including on NixOS.

The paired benchmark calls the real x0x decoder/ML-DSA verifier in both arms;
only shadow adds WB001 mapping, core admission and an ephemeral watermark.
Signatures are generated before measurement. 32 alternating-order paired rounds
of 64 inputs retain raw nanoseconds. 1/2/4 local observer threads exercise local
concurrency; they are not a distributed mesh. Report p50/p95/p99, wall throughput,
observer state size, total process CPU and peak RSS without claiming speedup.
There is no queue, journal or fsync in this observational path.

## Boundaries

- `announce_v3::IdentityAnnouncementV3::verify` remains the sole signature path:
  ML-DSA-65 key/id binding and machine signature. This verifies an announcement,
  not agent delegation, group membership or consent to execute an operation.
- Receiver supplies expected machine/agent, own receiver identity and freshness
  policy. The source cannot replace local policy. Disabling or dropping one
  observer has no effect on another.
- BNR envelope authority is the receiving observer. Its digest binds the exact
  original signed wire. No claim that the source signed the derived envelope.
- Fixed-size observer watermark is ephemeral. Lost/restarted state is not a
  durable replay ledger. No execution capability or signed receipt is emitted.
- Input <=8192 bytes; existing decoder's bounds and signature verifier remain.
  Decoding allocates transiently. Future ingress integration needs sampling and
  rate limits; this branch does not install it on the hot path.
- No Ed25519 host receipts, wallet, coordinator, new transport or cryptographic
  fallback. Post-quantum transport settings are unchanged. Claims remain source
  scoped; no new independent cryptographic audit was performed.
- Upstream #622 redirects remaining egress work to #504; #505 is field-accepted.
  This offline benchmark does not satisfy the per-peer wire-occupancy request.

## Validation

Results and exact receipt references are appended after execution. NixOS host
acceptance remains separate from Ubuntu/WSL or a Nix shell on Ubuntu. The
independent invitation-convergence failure on main is not repaired here.
