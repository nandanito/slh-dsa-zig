# Security policy

## Status

> 🚧 **`slh-dsa-zig` is EXPERIMENTAL and has not been audited. Do not use it to protect
> anything you care about.** This document describes the responsible disclosure path we will
> follow as the project matures, not a guarantee of audit-grade behaviour today.

The library is in **pre-1.0** development. Constant-time discipline, fuzz coverage, and
KAT validation are being built out incrementally. Until each component is marked ✅ in the
README status table *and* `v0.1.0` is tagged, treat **every** primitive as untrusted.

## Supported versions

| Version | Status | Security updates |
|---|---|---|
| `main`  | Active development | Issues fixed in-place; no backports |
| `0.x`   | Not yet released | n/a |

There is no LTS branch yet. Once a tagged release exists, this section will document the
support window.

## Reporting a vulnerability

If you believe you have found a security-relevant issue — anything from a constant-time
violation, a side-channel concern, a KAT mismatch that suggests a correctness bug, an
ADRS-encoding inconsistency, or an issue with how secret material is handled in memory —
please report it privately.

**Preferred channel:** [GitHub Security Advisory](https://github.com/nandanito/slh-dsa-zig/security/advisories/new).

**Backup channel:** email *(placeholder — to be filled in before first release; until then,
GitHub Security Advisory is the only supported channel)*.

Please include:

- The version (commit SHA) you tested against.
- The parameter set(s) affected, if applicable.
- A minimal reproducer or test vector.
- An assessment of the impact (correctness break, key recovery, side channel, etc.).
- Whether you have notified anyone else.

Please **do not** open a public issue or pull request for security-relevant findings until
we have had a chance to coordinate disclosure.

## Scope

**In scope:**

- Correctness bugs in the SLH-DSA construction (any of WOTS+, XMSS, hypertree, FORS, the
  top-level scheme, or the hash adapters).
- Constant-time violations on hot paths handling secret material.
- Memory-hygiene issues: failure to zeroise secrets, dependence on uninitialised memory,
  out-of-bounds access, use-after-free.
- KAT-vector mismatches with NIST ACVP.
- Build-system or CI changes that materially weaken the security posture (for example,
  silently disabling the constant-time job).

**Out of scope:**

- Anything in the `upstream-candidate/` tree that has not been merged to `main`.
- Performance-only issues that do not affect correctness or side-channel posture.
- Third-party dependencies (we currently have none).
- Theoretical attacks against SLH-DSA itself that apply equally to every conforming
  implementation. Direct those to NIST / IETF / the wider cryptographic community.

## Response expectations

Until the project has a paid maintainer, response is **best-effort on evenings and weekends**.
We commit to:

1. Acknowledging receipt within **7 days**.
2. Providing an initial assessment within **30 days**.
3. Coordinating a disclosure timeline with the reporter once the issue is understood.

These windows widen during travel or major release work. We will communicate proactively if
we cannot meet them.

## Disclosure timeline

For confirmed issues:

- **Coordination window:** typically 90 days from acknowledgement, or shorter if a fix is
  ready sooner. Negotiable for complex issues.
- **Patch release:** issued under a clear `SECURITY` advisory, with a CVE assigned where the
  reporter or we believe one is warranted.
- **Credit:** reporters are credited in the advisory and the release notes unless they ask
  not to be.

## Bug bounty

There is no bug bounty programme. Reporters of confirmed issues are credited in a "hall of
fame" section in this file and in release notes. A formal bounty may be considered once the
project has external funding.

## Hall of fame

*(Reserved. Will list reporters of confirmed issues here.)*

## Notes on threat model

SLH-DSA is designed to be secure against an attacker with access to a large-scale quantum
computer running Shor's and Grover's algorithms. This implementation aims to preserve that
property; we are *not* trying to defend against:

- Compromise of the signing host. SLH-DSA is a software signing scheme; if the host is
  compromised, signing keys are compromised.
- Physical side channels (power analysis, electromagnetic emanation, fault injection)
  without explicit hardware support.
- Implementation flaws in callers that, for example, sign attacker-controlled inputs without
  rate limiting.

The constant-time discipline in this library defends against software-observable timing
side channels (cache timing, branch prediction). Anything beyond that — fault attacks,
physical side channels, supply-chain compromise — requires defences outside this library.

## References

- FIPS 205, SLH-DSA: <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf>
- Original SPHINCS+ submission: <https://sphincs.org/>
- NIST ACVP server (test vectors): <https://github.com/usnistgov/ACVP-Server>

This policy is modelled on the security policies of
[libsodium](https://github.com/jedisct1/libsodium),
[age](https://github.com/FiloSottile/age/security/policy), and the
[RustCrypto](https://github.com/RustCrypto) project.
