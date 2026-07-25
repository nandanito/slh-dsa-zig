# Reference

Lookup material.

<div class="grid cards" markdown>

-   **[Parameter set tables](parameter-sets.md)**

    ---

    All twelve sets with every derived size — chain counts, digest field widths,
    and the per-component signature breakdown.

-   **[FIPS 205 map](spec-map.md)**

    ---

    Every algorithm number in the standard, mapped to the function that
    implements it.

-   **[Further reading](further-reading.md)**

    ---

    The standard, the SPHINCS+ papers, reference implementations, and the related
    RFCs.

</div>

## Quick facts

| | |
|---|---|
| Standard | FIPS 205, August 2024 |
| Parameter sets | 12 (3 security levels × 2 hash families × `s`/`f`) |
| Public key | `2n` bytes — 32 / 48 / 64 |
| Private key | `4n` bytes — 64 / 96 / 128 |
| Signature | 7,856 – 49,856 bytes |
| Winternitz `w` | 16 (`lg_w = 4`) for every set |
| Signature budget | up to `2^64` per key |
| Stateful? | **No** — that is the `SL` in SLH-DSA |
| Pre-hash variants | Defined by FIPS 205; **deferred** in this library |

## Commands

```sh
zig build                          # static library
zig build test                     # unit tests
zig build kat -- --mode keygen --vectors tests/vectors/keygen.json
zig build bench                    # benchmarks (ReleaseFast)
zig build bench -- --param-set SLH-DSA-SHAKE-128s --op sign
zig build fuzz                     # fuzz smoke; --fuzz=N for coverage-guided
zig build ctgrind                  # constant-time harness (run under Valgrind)
zig build examples                 # all examples
zig fmt --check .                  # format check (CI enforces)
```

Docs:

```sh
python3 -m venv .venv
.venv/bin/pip install -r docs/requirements.txt
.venv/bin/mkdocs serve             # http://127.0.0.1:8000
```
