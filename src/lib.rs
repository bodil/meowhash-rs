// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! # Meow Hasher
//!
//! An implementation of the [Meow hasher][meow-hasher] in native Rust providing
//! the [Digest][Digest] trait.
//!
//! The [Meow hasher][meow-hasher] is a hashing algorithm designed for hashing
//! large data sets (on the order of gigabytes) very efficiently. It takes about
//! 60 milliseconds to hash 1 gigabyte of data on an i7-7700 at 2.8GHz.
//!
//! It is *not* cryptographically secure.
//!
//! This implementation currently only supports the `x86`, `x86_64` and
//! `aarch64` architectures.
//!
//! [meow-hasher]: https://mollyrocket.com/meowhash
//! [Digest]: https://docs.rs/digest/latest/digest/trait.Digest.html

#![no_std]
#![forbid(rust_2018_idioms)]
#![deny(nonstandard_style)]
#![warn(unreachable_pub, missing_docs)]
#![cfg_attr(target_arch = "aarch64", feature(aarch64_target_feature, stdsimd))]

use core::mem;
use core::ptr;
use digest::generic_array::{
    typenum::{consts::*, Unsigned},
    GenericArray,
};
use digest::Digest;

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
mod x86;
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
use x86::{aes_merge, aes_rotate, Simd128};

#[cfg(target_arch = "aarch64")]
mod arm;
#[cfg(target_arch = "aarch64")]
use arm::{aes_merge, aes_rotate, Simd128};

#[derive(Clone, Copy)]
pub(crate) struct MeowLane {
    l0: Simd128,
    l1: Simd128,
    l2: Simd128,
    l3: Simd128,
}

#[inline]
pub(crate) unsafe fn aes_rotate_lanes(a: &mut MeowLane, b: &mut [MeowLane]) {
    aes_rotate(a, &mut b[0]);
    aes_rotate(a, &mut b[1]);
    aes_rotate(a, &mut b[2]);
    aes_rotate(a, &mut b[3]);
}

#[inline]
pub(crate) unsafe fn aes_merge_lanes(a: &mut [MeowLane], b: &[MeowLane]) {
    aes_merge(&mut a[0], &b[0]);
    aes_merge(&mut a[1], &b[1]);
    aes_merge(&mut a[2], &b[2]);
    aes_merge(&mut a[3], &b[3]);
}

impl MeowLane {
    pub(crate) fn new(seed: u128) -> Self {
        unsafe { core::mem::transmute([seed, seed, seed, seed]) }
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self as *const _ as *const u8,
                core::mem::size_of::<MeowLane>(),
            )
        }
    }
}
/// Meow hasher.
///
/// An implementation of the [Meow hasher][meow-hasher] providing the
/// [Digest][Digest] trait.
///
/// [meow-hasher]: https://mollyrocket.com/meowhash
/// [Digest]: https://docs.rs/digest/latest/digest/trait.Digest.html
pub struct MeowHasher {
    lanes: [MeowLane; 4],
    buf: [MeowLane; 4],
    index: usize,
    seed: u128,
}

impl Default for MeowHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl MeowHasher {
    /// Compute the hash of a chunk of data directly using the provided seed.
    pub fn digest_with_seed(seed: u128, data: &[u8]) -> GenericArray<u8, U64> {
        let mut hasher = MeowHasher::with_seed(seed);
        hasher.input(&data);
        hasher.result()
    }

    /// Create a new hasher instance with the provided seed.
    pub fn with_seed(seed: u128) -> Self {
        MeowHasher {
            lanes: [
                MeowLane::new(seed),
                MeowLane::new(seed),
                MeowLane::new(seed),
                MeowLane::new(seed),
            ],
            buf: [
                MeowLane::new(seed),
                MeowLane::new(seed),
                MeowLane::new(seed),
                MeowLane::new(seed),
            ],
            index: 0,
            seed,
        }
    }

    #[inline]
    fn block(&self) -> [MeowLane; 4] {
        [
            MeowLane::new(self.seed),
            MeowLane::new(self.seed),
            MeowLane::new(self.seed),
            MeowLane::new(self.seed),
        ]
    }

    #[inline]
    fn block_size() -> usize {
        mem::size_of::<[MeowLane; 4]>()
    }

    #[inline]
    fn left(&self) -> usize {
        Self::block_size() - self.index
    }

    #[inline]
    unsafe fn buf_ptr(&mut self) -> *mut u8 {
        (self.buf.as_ptr() as *mut u8).add(self.index)
    }

    unsafe fn feed(&mut self, data: &[u8]) {
        let mut src_ptr = data.as_ptr();
        let mut src_left = data.len();
        let mut buf_left = self.left();

        while src_left >= buf_left {
            ptr::copy_nonoverlapping(src_ptr, self.buf_ptr(), buf_left);

            aes_merge_lanes(&mut self.lanes, &self.buf);

            src_left -= buf_left;
            src_ptr = src_ptr.add(buf_left);
            buf_left = Self::block_size();
            self.index = 0;
        }

        if src_left > 0 {
            ptr::copy_nonoverlapping(src_ptr, self.buf_ptr(), src_left);
            self.index += src_left;
        }
    }

    unsafe fn finalise(&mut self) -> MeowLane {
        let mut r0 = MeowLane::new(self.seed);
        let empty = MeowLane::new(self.seed);

        if self.index > 0 {
            // Pad the last block if needed and merge it.
            let mut empty_block = self.block();
            let src_ptr = (&mut empty_block as *mut _ as *mut u8).add(self.index);
            let dest_ptr = self.buf_ptr();
            ptr::copy_nonoverlapping(src_ptr, dest_ptr, self.left());
            aes_merge_lanes(&mut self.lanes, &self.buf);
        }

        aes_rotate_lanes(&mut r0, &mut self.lanes);
        aes_rotate_lanes(&mut r0, &mut self.lanes);
        aes_rotate_lanes(&mut r0, &mut self.lanes);
        aes_rotate_lanes(&mut r0, &mut self.lanes);

        aes_merge(&mut r0, &empty);
        aes_merge(&mut r0, &empty);
        aes_merge(&mut r0, &empty);
        aes_merge(&mut r0, &empty);
        aes_merge(&mut r0, &empty);

        r0
    }
}

impl Digest for MeowHasher {
    type OutputSize = U64;

    fn new() -> Self {
        Self::with_seed(0)
    }

    fn input<B: AsRef<[u8]>>(&mut self, data: B) {
        unsafe { self.feed(data.as_ref()) }
    }

    fn chain<B: AsRef<[u8]>>(mut self, data: B) -> Self {
        self.input(data);
        self
    }

    fn result(mut self) -> GenericArray<u8, Self::OutputSize> {
        GenericArray::clone_from_slice(unsafe { self.finalise() }.as_bytes())
    }

    fn reset(&mut self) {
        *self = Self::with_seed(self.seed);
    }

    fn result_reset(&mut self) -> GenericArray<u8, Self::OutputSize> {
        let result = unsafe { self.finalise() };
        self.reset();
        GenericArray::clone_from_slice(result.as_bytes())
    }

    fn output_size() -> usize {
        Self::OutputSize::USIZE
    }

    /// Compute the hash of a chunk of data directly.
    fn digest(data: &[u8]) -> GenericArray<u8, Self::OutputSize> {
        let mut hasher = MeowHasher::with_seed(0);
        hasher.input(&data);
        hasher.result()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::collection::vec;
    use proptest::num::{u128, u8, usize};
    use proptest::proptest;

    proptest! {
        #[test]
        fn hash_same_data(seed in u128::ANY, blob in vec(u8::ANY, 0..65536)) {
            let mut hasher = MeowHasher::with_seed(seed);
            hasher.input(&blob);
            let hash1 = hasher.result();
            let hash2 = MeowHasher::digest_with_seed(seed, &blob);
            // Two hashes of the same data are equal
            assert_eq!(hash1, hash2);
        }

        #[test]
        fn hash_different_seeds(seed in u128::ANY, blob in vec(u8::ANY, 0..65536)) {
            let hash1 = MeowHasher::digest_with_seed(seed, &blob);
            let hash2 = MeowHasher::digest_with_seed(seed ^ 1, &blob);
            // Hashes with different seeds are not equal
            assert_ne!(hash1, hash2);
        }

        #[test]
        fn hash_different_data(seed in u128::ANY, mut blob in vec(u8::ANY, 1..65536), modify in usize::ANY) {
            let hash1 = MeowHasher::digest_with_seed(seed, &blob);
            let modify = modify % blob.len();
            blob[modify] ^= 1;
            let hash2 = MeowHasher::digest_with_seed(seed, &blob);
            // A blob with one bit modified hashes differently
            assert_ne!(hash1, hash2);
        }
    }
}
