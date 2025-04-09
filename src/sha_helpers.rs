#![allow(non_snake_case)]

use ark_ff::PrimeField;

// ========== Bit Conversion Utilities ========== //

/// Converts a hex string to a vector of bits (big-endian).
pub fn from_hex(hex: &str) -> Vec<u8> {
    let bytes = hex::decode(hex).expect("Invalid hex.");
    bytes
        .iter()
        .flat_map(|&byte| (0..8).rev().map(move |i| (byte >> i) & 1))
        .collect()
}

/// Converts an integer into a fixed-size big-endian bit array.
pub fn to_bits_be<T: Into<u64>, const N: usize>(num: T) -> [u8; N] {
    let n = num.into();
    std::array::from_fn(|i| ((n >> (N - 1 - i)) & 1) as u8)
}

/// Converts a bit slice into an array of field elements.
pub fn bits_to_field<F: PrimeField, const N: usize>(bits: &[u8]) -> [F; N] {
    let mut arr = [F::zero(); N];
    for (i, &bit) in bits.iter().enumerate().take(N) {
        arr[i] = F::from(bit);
    }
    arr
}

// ========== Padding Utilities ========== //

/// Pads the bit-level SHA256 message to exactly `max_bits`, according to the SHA256 specification.
/// This function performs bit-level padding including the 1-bit marker, 0-fill, and 64-bit length field.
/// It ensures the message ends at a complete block boundary defined by `max_bits`.
pub fn sha256_pad(input_bits: Vec<u8>, max_bits: usize) -> (Vec<u8>, usize) {
    // Pad the input to match SHA256 requirements.
    let mut padded = input_bits;
    let bit_length = padded.len();
    padded.push(1);

    while padded.len() % 512 != 448 {
        padded.push(0);
    }
    padded.extend_from_slice(&to_bits_be::<_, 64>(bit_length as u64));

    assert!(
        padded.len() % 512 == 0,
        "Padding did not complete properly!"
    );

    let pre_pad_len = padded.len();

    // Pad with zeros to reach max_bits.
    while padded.len() < max_bits {
        padded.push(0);
    }

    assert_eq!(
        padded.len(),
        max_bits,
        "Padding to max length did not complete properly! Your padded message is: {} long but expected: {}!",
        padded.len(),
        max_bits
    );

    // Index where the 64-bit message length field begins (i.e., right before the final 64 bits).
    let output_hash_index = pre_pad_len - 64;

    (padded, output_hash_index)
}

// ========== Field Bitwise Logic ========== //

/// Element-wise AND logic in the field.
pub fn and<F: PrimeField, const N: usize>(a: [F; N], b: [F; N]) -> [F; N] {
    std::array::from_fn(|i| a[i] * b[i])
}

/// Element-wise NOT logic in the field.
pub fn not<F: PrimeField, const N: usize>(a: [F; N]) -> [F; N] {
    std::array::from_fn(|i| F::one() - a[i])
}

/// Performs bitwise XOR in the field.
pub fn xor<F: PrimeField, const N: usize>(a: [F; N], b: [F; N]) -> [F; N] {
    let and_ab = and(a, b);
    std::array::from_fn(|i| a[i] + b[i] - F::from(2u8) * and_ab[i])
}

/// Bitwise rotate-right.
pub fn rotate_right<F: PrimeField, const N: usize>(rot: usize, word: [F; N]) -> [F; N] {
    let mut rotated = [F::zero(); N];
    for i in 0..N {
        rotated[(i + rot) % N] = word[i];
    }
    rotated
}

/// Logical right shift of a bit array represented in the field.
pub fn right_shift<F: PrimeField, const N: usize>(shift: usize, word: [F; N]) -> [F; N] {
    let mut shifted = [F::zero(); N];
    if shift < N {
        shifted[shift..].copy_from_slice(&word[..(N - shift)]);
    }
    shifted
}

/// Modular addition in binary form (mod 2^32).
pub fn wrapping_add<F: PrimeField>(a: [F; 32], b: [F; 32]) -> [F; 32] {
    let mut result = [F::zero(); 32];
    let mut carry = F::zero();
    let one = F::one();
    let two = one + one;

    for i in (0..32).rev() {
        let sum = a[i] + b[i] + carry;
        if sum >= two {
            result[i] = sum - two;
            carry = one;
        } else {
            result[i] = sum;
            carry = F::zero();
        }
    }

    result
}

// ========== Digest Utilities ========== //

/// Converts a 32-bit array of field elements to a `u32`, interpreting bits as big-endian.
pub fn bits_to_u32<F: PrimeField>(bits: [F; 32]) -> u32 {
    bits.iter().enumerate().fold(0u32, |acc, (i, bit)| {
        let b = if *bit == F::zero() { 0 } else { 1 };
        acc | (b << (31 - i))
    })
}

/// Converts final state words into a hex digest.
pub fn digest_to_hex<F: PrimeField>(H: [[F; 32]; 8]) -> String {
    H.iter()
        .map(|word| format!("{:08x}", bits_to_u32(*word)))
        .collect::<Vec<_>>()
        .join("")
}
