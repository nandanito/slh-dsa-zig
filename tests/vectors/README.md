# NIST ACVP Vectors for SLH-DSA

This directory holds NIST ACVP (Automated Cryptographic Validation
Protocol) Known-Answer Test vectors for SLH-DSA. The vectors themselves
are **not** checked into the repository:

- They are large (hundreds of MB across all parameter sets).
- They are regenerated periodically by NIST.
- Vendoring them would conflate "tests of this library" with "snapshot of
  NIST's test corpus."

The `.gitignore` excludes every `*.json` in this directory but keeps this
README.

## Where to get them

NIST publishes SLH-DSA vectors as part of the ACVP server project:

  <https://github.com/usnistgov/ACVP-Server>

Look under `gen-val/json-files/` for the SLH-DSA folders. There are three
vector types (called "modes" in ACVP terminology):

| Mode     | Inputs                       | Expected output     | What it tests           |
|----------|------------------------------|---------------------|-------------------------|
| `keyGen` | `SK.seed`, `SK.prf`, `PK.seed` | `pk`, `sk`        | `KeyPair.fromSeeds`     |
| `sigGen` | `sk`, `message`, `opt_rand?` | `signature`         | `sign`                  |
| `sigVer` | `pk`, `message`, `signature` | accept / reject     | `verify`                |

## Suggested layout

```
tests/vectors/
├── README.md                ← this file (tracked)
├── keygen.json              ← NIST keyGen prompts + expectedResults
├── siggen.json              ← NIST sigGen   prompts + expectedResults
└── sigver.json              ← NIST sigVer   prompts + expectedResults
```

Each file is the merged `prompts.json` + `expectedResults.json` from the
ACVP archive, or a subset filtered to the parameter sets you care about.

## Quick fetch

```sh
# Clone shallowly — we only want the JSON corpus.
git clone --depth=1 https://github.com/usnistgov/ACVP-Server.git /tmp/acvp

# Copy the SLH-DSA vector files of interest. The exact paths inside the
# upstream tree shift between releases; grep for `SLH-DSA` to locate them.
find /tmp/acvp -path '*SLH-DSA*' -name '*.json'
```

## Running the runner

Once a vector file is in place:

```sh
zig build kat -- --mode keygen --vectors tests/vectors/keygen.json
zig build kat -- --mode siggen --vectors tests/vectors/siggen.json
zig build kat -- --mode sigver --vectors tests/vectors/sigver.json
```

Add `--param-set SLH-DSA-SHAKE-128s` to restrict to one parameter set
while iterating.

## ACVP JSON shape (paraphrased)

```jsonc
{
  "vsId": 12345,
  "algorithm": "SLH-DSA",
  "mode": "keyGen",
  "testGroups": [
    {
      "tgId": 1,
      "parameterSet": "SLH-DSA-SHAKE-128s",
      "tests": [
        {
          "tcId": 1,
          "skSeed": "AABBCC...",
          "skPrf":  "AABBCC...",
          "pkSeed": "AABBCC...",
          // expected outputs are folded in from expectedResults.json:
          "pk": "AABBCC...",
          "sk": "AABBCC..."
        }
        // ...
      ]
    }
  ]
}
```

All hex strings are uppercase. The runner decodes them with
`runner.hexDecode`.

## Status

The runner skeleton (`tests/kat_runner.zig`) parses this structure and
dispatches per-parameter-set, but the executors currently return
`skipped` until the underlying scheme is implemented. See the project
roadmap in the top-level `README.md`.
