# confidential-container-launch

A confidential-container **launch gate** in Go (stdlib only): verify
attestation evidence against a workload manifest, and only on ALLOW seal the
workload's secrets under a **measurement-bound key** that a tampered container
cannot open.

## Why this exists

Confidential containers (CoCo) promise that a container runs inside a trusted
execution environment (TEE) where even the cloud operator cannot read its
memory. But that promise is only as good as the launch decision: before a
container receives its API keys and database passwords, someone must check
that the host actually measured the expected image, the expected launch
configuration, and the expected runtime configuration, on a platform patched
to an acceptable level, with fresh (not replayed) evidence.

That check is this project. It is the enforcement point where an attestation
policy turns into a launch decision plus a sealed secret bundle, the pattern
behind "attestation-gated secrets" for confidential containers.

> **Clean-room statement.** All concepts here are public: TDX measurement
> registers (MRTD, MRCONFIGID, RTMR0-3), REPORTDATA nonce binding, and
> measurement-bound secret release are documented in public confidential
> computing specifications. Every evidence file in `examples/` is synthetic,
> generated deterministically by `coco-launch gen-sample`. No
> Intel-internal code, APIs, or non-public details are used or implied.

## Architecture

```
                    +-------------------------------+
                    | manifest.json (operator)      |
                    |  workload + image digest      |
                    |  expected MRTD/MRCONFIGID/    |
                    |    RTMR0-3, nonce, TCB floor  |
                    +---------------+---------------+
                                    |
  +----------------+                v
  | evidence.json  |    +------------------------+     +------------------+
  | (attestation   |--->| internal/launch      |---->| plan.json          |
  |  report: MRTD, |    |  1. measurement match |     |  ALLOW or DENY     |
  |  RTMRs, SVN,   |    |  2. nonce binding     |     |  per-check reasons |
  |  REPORTDATA)   |    |  3. TCB floor         |     |  sealed secrets    |
  +-------+--------+    +-----------+------------+     |  (ALLOW only)    |
          |                         |                    +--------+---------+
          |              HKDF-SHA256(MRTD || MRCONFIGID || RTMR2)    |
          |                         |                    +--------v---------+
          |                         v                    | unseal: re-derive|
          |              AES-256-GCM seal each secret      | key from presented |
          +--------------------------> sealed bundle ----->| evidence; drift => |
                                                            | GCM auth failure |
                                                            +------------------+
```

The gate is deliberately ordered: measurement match first (wrong code),
then nonce binding (stale evidence), then the TCB floor (unpatched
platform). A DENY plan carries no sealed secrets. Sealing binds to MRTD
(the TD image), MRCONFIGID (launch configuration) and RTMR2 (runtime /
container configuration), so changing any of those after sealing produces a
different key and decryption fails closed.

## Quickstart

All commands below were verified live against this repository (Go 1.24.7,
`go test ./...` passing, see Tests).

```sh
# Build
go build -o coco-launch ./cmd/coco-launch

# Generate the synthetic sample set (manifest + evidence + demo secrets)
./coco-launch gen-sample --out-dir examples

# Launch gate: ALLOW, with a sealed secret bundle in plan.json
./coco-launch launch \
  --manifest examples/manifest.json \
  --evidence examples/evidence.json \
  --secrets examples/secrets.json \
  --out plan.json
# [pass] measurement:mr_td: matches manifest
# [pass] measurement:mr_config_id: matches manifest
# [pass] measurement:rtmr0: matches manifest
# [pass] measurement:rtmr1: matches manifest
# [pass] measurement:rtmr2: matches manifest
# [pass] measurement:rtmr3: matches manifest
# [pass] nonce-binding: REPORTDATA commits to manifest nonce
# [pass] tcb-floor: TEE_TCB_SVN meets minimum
# [pass] qe-svn: 3 >= 2
# [pass] pce-svn: 4 >= 2
# decision: ALLOW (plan written to plan.json)

# Unseal (simulated in-TEE side): prints the secrets back
./coco-launch unseal --bundle plan.json --evidence examples/evidence.json
# {
#   "api_key": "demo-only-not-a-real-key",
#   "db_password": "demo-only-not-a-real-password"
# }

# Inspect one evidence file
./coco-launch inspect --evidence examples/evidence.json
```

Try the failure modes yourself: change one hex digit in `rtmr2` in a copy of
`evidence.json` and `launch` exits 1 with `decision: DENY` and no sealed
secrets; unseal the ALLOW bundle against that drifted evidence and you get
`authentication failed; measurements drifted or bundle tampered`.

## API reference

### CLI

| Command | Purpose |
| --- | --- |
| `coco-launch gen-sample --out-dir DIR` | Write deterministic synthetic `manifest.json`, `evidence.json`, `secrets.json` |
| `coco-launch launch --manifest M --evidence E --secrets S --out P` | Run the gate; write plan `P`; exit 1 on DENY |
| `coco-launch unseal --bundle P --evidence E [--out FILE]` | Re-derive the key from `E` and decrypt the bundle (stdout by default) |
| `coco-launch inspect --evidence E` | Print measurements, SVN levels and REPORTDATA |

### Evidence format (`internal/evidence`)

JSON with `version` (must be 4), `tee_type` (`"tdx"`), 48-byte hex
`mr_td`, `mr_config_id`, `mr_owner`, `rtmr0`-`rtmr3`, 64-byte hex
`report_data`, 16-byte hex `tee_tcb_svn`, and integer `qe_svn` /
`pce_svn`. `Validate()` checks structure only; it never claims authenticity.

Nonce binding rule: `report_data[0:32]` must equal `SHA-256(nonce)` from
the manifest. The remaining 32 bytes are reserved (zero in samples).

### Gate (`internal/launch`)

- `LoadManifest(path)`, `Evaluate(manifest, evidence, secrets) (*Plan, error)`:
  a DENY is a returned plan, not an error; only malformed inputs error.
- `DeriveKey(evidence)`: HKDF-SHA256 (RFC 5869, stdlib HMAC) over
  MRTD || MRCONFIGID || RTMR2, salt `SHA-256("coco-launch-v1")`.
- `Seal(key, plaintext)` / `Unseal(evidence, sealed)`: AES-256-GCM,
  random nonce per secret, base64-encoded in the plan.

## What this demonstrates (interview talking points)

- **Attestation as an enforcement point, not a report.** The gate does not
  just log measurements; it converts them into a binary launch decision and
  controls secret release.
- **Freshness is a separate check from identity.** Matching measurements
  prove *what* ran; REPORTDATA nonce binding proves *when* it was measured,
  which is what defeats replay of last week's good evidence.
- **Sealing vs. encryption.** Encrypting with a measurement-derived key
  means the ciphertext is useless outside the measured configuration; there
  is no key to steal, only measurements to match.
- **Fail-closed ordering.** Every check is reported individually, but any
  single failure denies the launch and suppresses the sealed bundle; there
  is no partial-release path.
- **Component-wise TCB comparison.** The TCB floor compares each SVN
  component, because one lagging component (say, microcode) is enough to
  distrust the platform even if the rest are current.

## Limitations / how I'd productionize it

- **No real quote verification.** This demo consumes JSON evidence, not
  binary TDX quotes, and does not verify signatures, the PCK certificate
  chain, QE identity, or Intel collateral. In production, a real quote
  verifier (e.g. Intel Trust Authority or an equivalent) sits in front of
  this gate, and this gate consumes its verified output.
- **No real TEE.** `unseal` takes an evidence file as a proxy for the TEE's
  own self-measurement. In production the unseal step runs inside the TEE
  (e.g. via a CoCo agent / key broker), never on the host CLI.
- **Demo KDF, not a KMS.** The HKDF derivation is correct but the "key
  broker" here is local. Production would use a key broker service with
  its own attestation, key wrapping, audit logging, and rotation.
- **No revocation or policy versioning.** A production gate needs revoked
  measurement lists, manifest signatures, and policy rollout/rollback.
- **Single workload, local files.** Multi-tenant policy storage, mTLS to
  the key broker, and Kubernetes admission integration are out of scope.

## Tests

```sh
go test ./...
```

Covers: ALLOW + unseal roundtrip, tampered measurement denies with no
sealed secrets, replayed evidence (unbound REPORTDATA) denies, stale TCB
denies, drifted RTMR2 cannot unseal, tampered bundle cannot unseal, and
malformed evidence is rejected.
