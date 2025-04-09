#![allow(non_snake_case)]

use std::marker::PhantomData;

use ark_ff::{PrimeField, UniformRand};

use kimchi::{
    mina_curves::pasta::Fp,
    o1_utils::{tests, FieldHelpers},
};
use sha2::{Digest, Sha256};

use crate::{constants::*, sha_helpers::*};

/// Native SHA256 implementation using field elements.
/// This is used to simulate and test SHA256 logic before building a circuit-compatible version.
pub struct NativeSha256<F: PrimeField> {
    padded_preimage: Vec<u8>,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> NativeSha256<F> {
    /// Constructor.
    pub fn new(padded_preimage: Vec<u8>) -> Self {
        Self {
            padded_preimage,
            _marker: PhantomData,
        }
    }

    /// Processes a single 512-bit message chunk, applying SHA256 compression.
    /// Updates internal state by applying 64 rounds of the SHA256 schedule and mixing.
    fn process_chunk(&mut self, bits: &[u8], state: &mut [[F; 32]; 8], K: [[F; 32]; 64]) {
        assert_eq!(bits.len(), 512, "Chunk must be 512 bits");

        // Message schedule W.
        let field_values = bits_to_field::<F, 512>(&bits);
        let mut W = [[F::zero(); 32]; 64];
        for (i, chunk) in field_values.chunks_exact(32).enumerate() {
            W[i].copy_from_slice(chunk);
        }

        for i in 16..64 {
            let s0 = xor(
                xor(rotate_right(7, W[i - 15]), rotate_right(18, W[i - 15])),
                right_shift(3, W[i - 15]),
            );
            let s1 = xor(
                xor(rotate_right(17, W[i - 2]), rotate_right(19, W[i - 2])),
                right_shift(10, W[i - 2]),
            );
            W[i] = wrapping_add(wrapping_add(s1, W[i - 7]), wrapping_add(s0, W[i - 16]));
        }

        // Compression loop.
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
            state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
        );

        for i in 0..64 {
            let S1 = xor(
                xor(rotate_right(6, e), rotate_right(11, e)),
                rotate_right(25, e),
            );
            let Ch = xor(and(e, f), and(not(e), g));
            let T1 = wrapping_add(
                wrapping_add(wrapping_add(wrapping_add(h, S1), Ch), K[i]),
                W[i],
            );

            let S0 = xor(
                xor(rotate_right(2, a), rotate_right(13, a)),
                rotate_right(22, a),
            );
            let Maj = xor(xor(and(a, b), and(a, c)), and(b, c));
            let T2 = wrapping_add(S0, Maj);

            h = g;
            g = f;
            f = e;
            e = wrapping_add(d, T1);
            d = c;
            c = b;
            b = a;
            a = wrapping_add(T1, T2);
        }

        // Final state update.
        state[0] = wrapping_add(a, state[0]);
        state[1] = wrapping_add(b, state[1]);
        state[2] = wrapping_add(c, state[2]);
        state[3] = wrapping_add(d, state[3]);
        state[4] = wrapping_add(e, state[4]);
        state[5] = wrapping_add(f, state[5]);
        state[6] = wrapping_add(g, state[6]);
        state[7] = wrapping_add(h, state[7]);
    }

    /// Computes the SHA256 hash over the (already padded) input bitstream.
    pub fn hash(mut self) -> [[F; 32]; 8] {
        assert!(
            &self.padded_preimage.len() % 512 == 0,
            "Input must be padded to 512-bit blocks."
        );

        let mut state = initial_state();
        let K = round_constants();

        let chunks: Vec<Vec<u8>> = self
            .padded_preimage
            .chunks(512)
            .map(|chunk| chunk.to_vec())
            .collect();

        for chunk in chunks {
            self.process_chunk(&chunk, &mut state, K);
        }

        // Output digest as [[F; 32]; 8] bit representation.
        state
    }
}

/// Tests native SHA256 logic against Rust's standard `sha2` implementation.
#[test]
fn native_sha256_test() {
    // === Test 1: SHA256 of a zero byte ===
    let zero_bits = from_hex("00");
    let (padded, _) = sha256_pad(zero_bits, 512);
    let zero_hash = NativeSha256::<Fp>::new(padded).hash();
    // Output digest as hex string.
    let zero_hash_hex = digest_to_hex(zero_hash);

    // Standart Sha256.
    let zero_std = Sha256::digest(&[0u8]);
    let zero_std_hex = hex::encode(zero_std);

    assert_eq!(zero_hash_hex, zero_std_hex, "Mismatch on 0x00.");

    // === Test 2: SHA256 of a random field elements ===
    let mut rng = tests::make_test_rng(None);
    let first_random = Fp::rand(&mut rng);
    let second_random = Fp::rand(&mut rng);
    let first_random_hex = first_random.to_hex();
    let second_random_hex = second_random.to_hex();
    let concatenated = format!("{}{}", first_random_hex, second_random_hex);

    let bits = from_hex(&concatenated);
    let (padded, digest_index) = sha256_pad(bits, 1024);
    let hash_index = 960;
    let native_hash = NativeSha256::<Fp>::new(padded).hash();
    // Output digest as hex string.
    let native_hash_hex = digest_to_hex(native_hash);

    // Standart Sha256.
    let bytes = hex::decode(&concatenated).unwrap();
    let std_hash = Sha256::digest(&bytes);
    let std_hash_hex = hex::encode(std_hash);

    assert_eq!(
        hash_index, digest_index,
        "Mismatch between hash index and expected hash index."
    );

    assert_eq!(
        native_hash_hex, std_hash_hex,
        "Mismatch between native and standard SHA256."
    );

    // === Test 3: SHA256 of a random field elements ===
    // Given random 4 Fp elements.
    let rand_numbers = [
        Fp::rand(&mut rng),
        Fp::rand(&mut rng),
        Fp::rand(&mut rng),
        Fp::rand(&mut rng),
    ];
    let rand_numbers_hex: Vec<String> = rand_numbers.iter().map(|num| num.to_hex()).collect();
    let merged_hex: String = rand_numbers_hex
        .iter()
        .flat_map(|num| num.chars())
        .collect();

    let bits = from_hex(&merged_hex);
    let (padded, digest_index) = sha256_pad(bits, 1536);
    let hash_index = 1472;
    let native_hash = NativeSha256::<Fp>::new(padded).hash();
    // Output digest as hex string.
    let native_hash_hex = digest_to_hex(native_hash);

    // Standart Sha256.
    let bytes = hex::decode(&merged_hex).unwrap();
    let std_hash = Sha256::digest(&bytes);
    let std_hash_hex = hex::encode(std_hash);

    assert_eq!(
        hash_index, digest_index,
        "Mismatch between hash index and expected hash index."
    );

    assert_eq!(
        native_hash_hex, std_hash_hex,
        "Mismatch between native and standard SHA256."
    );
}
