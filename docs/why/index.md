# Why

Two questions worth answering before any of the machinery makes sense.

<div class="grid cards" markdown>

-   **[Why post-quantum?](post-quantum.md)**

    ---

    Shor's algorithm does not weaken RSA and elliptic curves. It ends them.
    What that means in practice, why signatures are on a different clock from
    encryption, and why "we'll migrate when quantum computers arrive" is the
    wrong plan.

-   **[Why hash-based?](hash-based.md)**

    ---

    Of the post-quantum signature families, hash-based is the oldest, the
    least mathematically adventurous, and by far the most expensive. That
    combination is exactly why it was standardised.

</div>

The short version: the signatures protecting today's software updates,
certificates and secure boot chains rest on two problems a quantum computer
solves efficiently. Replacements exist. SLH-DSA is the replacement that
requires believing the least.
