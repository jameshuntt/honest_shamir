# honest_shamir

Shamir secret sharing over GF(2^8), on the [`honest`](https://crates.io/crates/honest)
field. Plain bytes in, plain bytes out.

A secret of any length is split into `n` shares so that any `k` of them
rebuild it and any `k − 1` reveal nothing. Each byte of the secret is the
constant term of its own random polynomial of degree `k − 1`; share `i`
holds every polynomial evaluated at `x = i`. Shares are the length of the
secret and `n` is at most 255.

```rust
use honest_shamir::{split, reconstruct, refresh, Threshold};

let threshold = Threshold::new(3, 5).unwrap();
let mut shares = split(b"the key to the archive", threshold).unwrap();

// any three shares rebuild the secret; order does not matter
let some = [shares[4].clone(), shares[0].clone(), shares[2].clone()];
assert_eq!(reconstruct(&some, threshold).unwrap(), b"the key to the archive");

// fewer than three is refused
assert!(reconstruct(&shares[..2], threshold).is_err());

// re-randomize: same secret, new shares, the old ones no longer combine with them
refresh(&mut shares, threshold).unwrap();
assert_eq!(reconstruct(&shares[1..4], threshold).unwrap(), b"the key to the archive");
```

`split` and `refresh` use the operating system's generator (feature
`os-rng`, on by default). `split_with` and `refresh_with` take any
`rand_core::TryCryptoRng`, for hosts that bring their own randomness or
for reproducible fixtures.

## What is checked, and what is not

- A `Threshold` needs `2 <= k <= n`. A 1-of-`n` split would hand the secret
  itself to every holder, so it is refused.
- Share sets are checked for distinct, non-zero indexes and equal lengths.
- Shares are **not** authenticated. A wrong or tampered share rebuilds a
  wrong secret without complaint. Keep a digest beside the shares, or let
  the AEAD tag on whatever the secret unlocks be the check.
- The bytes of a `Share` are zeroized on drop and never printed by `Debug`;
  the coefficient buffers used during a split are zeroized too. The secret
  you pass in and the `Vec<u8>` you get back are yours to scrub. The
  `classified_shamir` crate does that part with `classified` containers.

The arithmetic does not branch on secret values: `honest::Gf256` multiplies
by masks and shifts, and the Lagrange basis depends only on the share
indexes, which are public.

## API

| item | does |
|---|---|
| `Threshold::new(k, n)` | the policy; `required()` and `total()` read it back |
| `split(secret, t)` / `split_with(secret, t, rng)` | `n` shares |
| `reconstruct(shares, t)` | the secret from the first `k` shares |
| `refresh(shares, t)` / `refresh_with(shares, t, rng)` | new shares for the same secret |
| `Share::new(index, bytes)` | a share received from elsewhere; `index()`, `bytes()`, `into_bytes()` |

`no_std` with `alloc` when the `std` feature is off.

## License

MIT OR Apache-2.0.
