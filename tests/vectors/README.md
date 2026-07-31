# NIST ACVP Vectors for SLH-DSA

This directory holds NIST ACVP (Automated Cryptographic Validation
Protocol) Known-Answer Test vectors for SLH-DSA. The vectors themselves
are **not** checked into the repository:

- They are large (the sigGen file alone is ~38 MB).
- They are regenerated periodically by NIST.
- Vendoring them would conflate "tests of this library" with "snapshot of
  NIST's test corpus."

The `.gitignore` excludes every `*.json` in this directory but keeps this
README.

## Where to get them

NIST publishes SLH-DSA vectors as part of the ACVP server project:

  <https://github.com/usnistgov/ACVP-Server>

Each ACVP algorithm folder ships several JSON files. The one this runner
wants is **`internalProjection.json`** — a single self-contained file that
merges the prompts (inputs) with the expected results (outputs), which is
exactly the shape the runner walks. The three folders we care about:

| Folder (under `gen-val/json-files/`) | Copy its `internalProjection.json` to |
|--------------------------------------|---------------------------------------|
| `SLH-DSA-keyGen-FIPS205`             | `tests/vectors/keygen.json`           |
| `SLH-DSA-sigGen-FIPS205`             | `tests/vectors/siggen.json`           |
| `SLH-DSA-sigVer-FIPS205`             | `tests/vectors/sigver.json`           |

Direct raw URLs (branch `master`):

```
https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/SLH-DSA-keyGen-FIPS205/internalProjection.json
https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/SLH-DSA-sigGen-FIPS205/internalProjection.json
https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/SLH-DSA-sigVer-FIPS205/internalProjection.json
```

These are the `isSample: true` demonstration vectors published in-tree; they
cover all 12 parameter sets and are what the runner validates against.

## Quick fetch

The repo is large, so use a shallow, blobless, sparse checkout to pull only
the three SLH-DSA folders:

```sh
git clone --depth=1 --filter=blob:none --sparse \
  https://github.com/usnistgov/ACVP-Server.git /tmp/acvp
cd /tmp/acvp
git sparse-checkout set \
  gen-val/json-files/SLH-DSA-keyGen-FIPS205 \
  gen-val/json-files/SLH-DSA-sigGen-FIPS205 \
  gen-val/json-files/SLH-DSA-sigVer-FIPS205

# Then, from the slh-dsa-zig checkout:
J=/tmp/acvp/gen-val/json-files
cp "$J/SLH-DSA-keyGen-FIPS205/internalProjection.json" tests/vectors/keygen.json
cp "$J/SLH-DSA-sigGen-FIPS205/internalProjection.json" tests/vectors/siggen.json
cp "$J/SLH-DSA-sigVer-FIPS205/internalProjection.json" tests/vectors/sigver.json
```

## Pinned commit (CI)

CI does not fetch from a moving branch. The `kat` job in
`.github/workflows/ci.yml` pins a specific ACVP-Server commit so a NIST regen
cannot silently change what the build validates:

```
ACVP_COMMIT = 112690e8484dba7077709a05b1f3af58ddefdd5d   # RELEASE/v1.1.0.40 (2025-06-12)
```

This is the last release that changed the SLH-DSA vector folders; content
served at a commit SHA is immutable, so the pin fixes the exact corpus. CI
fetches the three files by raw URL at that SHA — e.g.

```
https://raw.githubusercontent.com/usnistgov/ACVP-Server/112690e8484dba7077709a05b1f3af58ddefdd5d/gen-val/json-files/SLH-DSA-keyGen-FIPS205/internalProjection.json
```

**Bumping the pin** (deliberate, not automatic): pick the new commit, update
`ACVP_COMMIT` in `ci.yml` and the value above, re-fetch locally, and re-run all
three modes to confirm the implementation still matches before merging. The
pinned corpus currently passes keyGen 120/120, sigGen 624/624, sigVer 504/504,
with nothing skipped.

## Running the runner

```sh
zig build kat -- --mode keygen --vectors tests/vectors/keygen.json
zig build kat -- --mode siggen --vectors tests/vectors/siggen.json
zig build kat -- --mode sigver --vectors tests/vectors/sigver.json
```

Add `--param-set SLH-DSA-SHAKE-128s` to restrict to one parameter set while
iterating. The `s` parameter sets sign slowly under `Debug`; build the
runner in `ReleaseFast` for a full sweep:

```sh
zig build kat -Doptimize=ReleaseFast -- --mode siggen --vectors tests/vectors/siggen.json
```

## ACVP JSON shape

Every mode shares the outer envelope:

```jsonc
{
  "vsId": 12345,
  "algorithm": "SLH-DSA",
  "mode": "keyGen" | "sigGen" | "sigVer",
  "revision": "FIPS205",
  "testGroups": [
    { "tgId": 1, "parameterSet": "SLH-DSA-SHAKE-128s", "tests": [ ... ] }
  ]
}
```

All byte strings are uppercase hex; the runner decodes them with
`runner.hexDecode`. Fields consumed per mode:

### keyGen

| Level | Field                     | Meaning                            |
|-------|---------------------------|------------------------------------|
| test  | `skSeed`, `skPrf`, `pkSeed` | key-generation seeds (inputs)    |
| test  | `pk`, `sk`                | expected public / secret key       |

Exercises `KeyPair.fromSeeds`.

### sigGen

Test **groups** carry the signing configuration:

| Group field          | Values                          | Effect                                              |
|----------------------|---------------------------------|-----------------------------------------------------|
| `signatureInterface` | `internal` / `external`         | `signInternal` (M direct) vs `signWithContext`      |
| `deterministic`      | `true` / `false`                | `opt_rand` = PK.seed (null) vs `additionalRandomness` |
| `preHash`            | `none` / `pure` / `preHash`     | `preHash` selects `signPreHash` (see below)         |

Per **test**:

| Field                 | When present            | Meaning                          |
|-----------------------|-------------------------|----------------------------------|
| `sk`                  | always                  | secret key (input)               |
| `message`             | always                  | message to sign                  |
| `context`             | external interface      | context string (may be empty)    |
| `additionalRandomness`| non-deterministic only  | the per-signature randomiser     |
| `signature`           | always                  | **expected** signature           |

The runner signs and compares byte-for-byte against `signature`.

### sigVer

| Group field          | Values                      | Effect                                    |
|----------------------|-----------------------------|-------------------------------------------|
| `signatureInterface` | `internal` / `external`     | `verifyInternal` vs `verifyWithContext`   |
| `preHash`            | `none` / `pure` / `preHash` | `preHash` selects `verifyPreHash`         |

Per **test**:

| Field         | When present       | Meaning                                     |
|---------------|--------------------|---------------------------------------------|
| `pk`          | always             | public key (input)                          |
| `message`     | always             | message                                     |
| `context`     | external interface | context string (may be empty)               |
| `signature`   | always             | signature to check                          |
| `testPassed`  | always             | **expected** accept (`true`) / reject       |

Negative cases include wrong-length signatures ("too large" / "too small");
a length mismatch cannot form the fixed-size signature array and is scored
as a rejection, matching `testPassed: false`.

## HashSLH-DSA (pre-hash) groups

Both sigGen and sigVer include `preHash: "preHash"` groups exercising the
HashSLH-DSA pre-hash variant, where a `hashAlg` is applied to the message
before signing (FIPS 205 §10.2.2 Algorithm 23 / §10.3 Algorithm 25). These
run against `signPreHash` / `verifyPreHash`.

Two details of the vector format matter for the runner:

- **`preHash` is a group-level axis; `hashAlg` is a per-test field.** ACVP
  varies the pre-hash function *within* a single group, so the function has to
  be read per test case, not per group.
- **Every test carries `hashAlg`, including pure ones**, where its value is
  `"none"`. So the presence of the field says nothing — the group's `preHash`
  value is what decides whether a pre-hash function applies.

Pre-hash groups are always `signatureInterface: "external"`; the two axes are
orthogonal in the schema but only one combination occurs.

The twelve `hashAlg` names in use are `SHA2-224`, `SHA2-256`, `SHA2-384`,
`SHA2-512`, `SHA2-512/224`, `SHA2-512/256`, `SHA3-224`, `SHA3-256`, `SHA3-384`,
`SHA3-512`, `SHAKE-128`, and `SHAKE-256`. Note that ACVP hyphenates the XOF
names, unlike FIPS 205's `SHAKE128` / `SHAKE256`.

## Status

`keyGen`, `sigGen`, and `sigVer` modes are fully wired (issues #25, #45).
Against the ACVP sample vectors, all three pass across the 12 parameter sets
for all three signature interfaces — internal, external (pure), and pre-hash.
No group is skipped by design.
