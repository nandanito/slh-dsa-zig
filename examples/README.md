# Examples

Small runnable programs demonstrating the planned slh-dsa-zig API.

> 🚧 Every example here will `@panic` until the scheme implementation
> lands. They exist to lock down the public API surface and to give
> downstream users a real reference for how the library will be called.

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
- Examples never panic on the *happy path* (once the implementation
  lands); a tamper-detection check that the verifier rejected a flipped
  bit is fine.
- Each example is a self-contained `pub fn main`. No helper modules.
- Examples use parameter sets via the comptime constructor:
  `slh_dsa.Slh_Dsa(.slh_dsa_shake_128s)`. Pick `s` for small signatures
  and slow signing, `f` for fast signing and larger signatures.
