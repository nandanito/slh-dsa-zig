# The two-lane rule

This repository has two lanes with **different rules about AI assistance**. If you
contribute, or if you are an AI assistant working here, this page is the one that
matters most.

## The lanes

### Lane A — everything outside `upstream-candidate/`

The standalone library (`src/`), tests, benchmarks, examples, the build script, CI,
and these docs.

**AI assistance is welcome.** Drafting code, proposing architectures, writing
tests, refactoring, fixing bugs — all fine.

### Lane B — `upstream-candidate/`

Reserved for code intended for eventual contribution to Zig's `std.crypto`.

**The Ziglang project does not accept AI-generated code into `std`.** So that
directory is human-authored only, with no exceptions — not stubs, not typo fixes,
not "obvious" one-liners.

The rules for an AI assistant working in this repo:

1. **Never write code in `upstream-candidate/`.** If a file there needs to change,
   stop and say so.
2. **Never copy from `src/` into `upstream-candidate/`.** The point of Lane B is an
   *independent* reading of FIPS 205. Cross-pollination destroys that, and it is
   the failure mode the rule exists to prevent.
3. **Reading is allowed** — to answer questions or review human-written code, when
   asked, as a critic and never as an author.
4. **Non-code artifacts** (a README, a doc page) may be assisted, but the boundary
   crossing must be flagged explicitly and confirmed first.

When the lane is genuinely ambiguous: **ask**. If still ambiguous, assume Lane B
and explain rather than write.

## Why bother

Two independent implementations of the same specification are worth more than one,
and the second one's value depends entirely on its independence.

Lane B is a from-scratch reading of FIPS 205 by a human who has already
implemented it once in Lane A. Where the two disagree, one is wrong — and that
disagreement is a genuinely strong signal, far stronger than either implementation
agreeing with itself. Copying between them, or having the same AI draft both, would
produce two implementations that share their mistakes. That is not independence; it
is duplication wearing a disguise.

The provenance requirement is also simply **upstream's rule**, not a preference to
be negotiated. Code with muddled provenance cannot be contributed at all, and
discovering that after writing it wastes the entire effort.

## CI enforces it

Every commit touching `upstream-candidate/` must carry:

```
Lane B compliant: human-authored, no AI assistance.
```

`ci.yml` has a `lane-b-trailer` job that rejects PRs violating this.

!!! danger "The trailer is an attestation, not a formality"

    An AI assistant must **never** add that trailer to its own commits. CI treats
    its presence as meaning human-authored. Adding it to AI-assisted work is not a
    process slip — it is a false statement about provenance, and it silently
    poisons the thing the whole arrangement exists to protect.

    Conversely, Lane A commits must **never** carry it. A commit co-authored by an
    AI does not belong in `upstream-candidate/` at all.

## Which lane is this?

Heuristics that resolve most cases:

| Signal | Lane |
|---|---|
| "upstream", "for std.crypto", "pure human", "I want to write this myself", "study" | **B** |
| "the library", "the test runner", "the benchmark", "fix CI", "add an example" | **A** |
| Anything in `src/`, `tests/`, `bench/`, `examples/`, `build.zig`, `.github/`, `docs/` | **A** |
| Anything in `upstream-candidate/` | **B** |

**These docs are Lane A.** They describe the standalone library. They deliberately
do not walk through Lane B's code, and they do not reproduce Lane A implementation
details in a form that would contaminate an independent reading — the component
pages cite FIPS 205 sections and discuss `src/`, which is exactly the material a
Lane B author is meant to derive independently. A Lane B author should read the
standard, not this site.

## Contributing

`CONTRIBUTING.md` has the full process. In brief:

- One concern per PR. Do not bundle a WOTS+ implementation with a CI tweak.
- Reference the FIPS 205 sections implemented.
- All status checks green: `fmt`, `build-test` (x86_64 + ARM64, Debug +
  ReleaseSafe), `kat`, and `lane-b-trailer` if applicable.
- Never push to `main` directly. Branch → PR → review → merge.

And the citation rule, which applies everywhere: cite the **final FIPS 205 (August
2024)**, never the initial public draft. The final standard inserted `gen_len2` as
Algorithm 1 in §3.2, shifting every later algorithm number by one. Verify against
the PDF — a number recalled from memory or copied from a draft-era source is very
likely wrong.
