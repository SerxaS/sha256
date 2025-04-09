# 🧬 Dynamic SHA256 in Rust with Field Elements

This Rust project provides a **dynamic, bit-level implementation of the SHA256 hash function** using arithmetic over finite fields. It is designed to be circuit-compatible and tested against Rust’s standard `sha2` library. The code supports both **native** and **dynamic** hashing engines and simulates SHA256 logic over field elements for use in zero-knowledge proof systems such as those built with `kimchi`.

---

## ✨ Features

- 🔐 **Field-based SHA256 logic**: Each 32-bit word of SHA256 is represented using `[F; 32]` field elements.
- 🔁 **Dynamic SHA256 engine**: Allows block-by-block hashing, suitable for streaming or recursive proofs.
- 📦 **Native SHA256 engine**: Fully processes a padded preimage and matches standard `sha2` outputs.
- 🧪 **Test suite**: Validates all hashing logic against the standard Rust `sha2` crate.
- ⚙️ **Utilities** for bit-level conversion, padding, bitwise field logic, and digest formatting.

---

## 📁 Project Structure

```text
src/
├── constants.rs        # SHA256 constants in field form (H, K)
├── dynamic_sha256.rs   # Dynamic block-by-block SHA256 engine
├── native_sha256.rs    # Full one-shot SHA256 hashing engine
├── sha_helpers.rs      # Bitwise helpers, padding logic, field logic
└── lib.rs              # Module exports
```

---

## 🧪 Tests

Run with:

```bash
cargo test
```

Includes:

- Hash of zero bytes
- Hash of random field elements
- Comparison with standard `sha2::Sha256`

---

## 📦 Dependencies

- [`ark-ff`](https://docs.rs/ark-ff): Finite field arithmetic.
- [`kimchi`](https://github.com/o1-labs/proof-systems): ZK circuit library (for `Fp` and `o1_utils`).
- [`sha2`](https://crates.io/crates/sha2): Used only for reference in tests.
- [`hex`](https://crates.io/crates/hex): For encoding/decoding between hex and bytes.

---

## 🔭 Purpose

This implementation is designed to:

- Simulate SHA256 in a form compatible with ZK circuits.
- Serve as a reference for future recursive or proof-compatible SHA256 gadgets.
- Enable partial hash computations (e.g. with tracked digest index).

---

## 🛠️ Usage Example

```rust
use dynamic_sha256::DynamicSha256;
use kimchi::mina_curves::pasta::Fp;
use sha_helpers::{from_hex, sha256_pad};

let input = from_hex("00");
let (padded, index) = sha256_pad(input, 512);
let hash = DynamicSha256::<Fp>::new(padded, index, None).hash();
```

---

## 📜 License

MIT or Apache 2.0 — choose whichever suits your project.

---

## 🙌 Acknowledgements

- Inspired by [o1js-dynamic-sha256](https://github.com/Shigoto-dev19/o1js-dynamic-sha256).
- Based on SHA256 spec and tailored for zk-friendly environments.
