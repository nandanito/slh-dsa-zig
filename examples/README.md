# Examples

Small runnable programs demonstrating the slh-dsa-zig API.

> 🚧 The library is **EXPERIMENTAL — do not use in production.** The examples
> themselves run: key generation, signing, and verification are implemented and
> validated against the NIST ACVP vectors. The banner is about the absence of a
> third-party audit, not about missing functionality.

## Running

```sh
zig build example_basic_sign
```

Each example registers its own `example_<name>` build step. To build all
examples without running:

```sh
zig build examples
```

## Index

| Name           | What it shows                                                  |
|----------------|----------------------------------------------------------------|
| `basic_sign`   | KeyPair generation, sign, verify, and tamper-rejection.        |

## Conventions

- Examples import the library as `@import("slh_dsa")`, the module name
  set up by `build.zig`.
- Examples never panic on the *happy path*; a tamper-detection check that
  the verifier rejected a flipped bit is fine.
- Each example is a self-contained `pub fn main`. No helper modules.
- Examples use parameter sets via the comptime constructor:
  `slh_dsa.Slh_Dsa(.slh_dsa_shake_128s)`. Pick `s` for small signatures
  and slow signing, `f` for fast signing and larger signatures.
