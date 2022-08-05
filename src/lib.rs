// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! # Meow Hasher
//!
//! An implementation of the [Meow hasher][meow-hasher] in native Rust providing
//! the [Digest][Digest] trait.
//!
//! The [Meow hasher][meow-hasher] is a hashing algorithm designed for hashing
//! large data sets (on the order of gigabytes) very efficiently.
//!
//! It is *not* cryptographically secure.
//!
//! This implementation currently only supports the `x86` and `x86_64`
//! architectures.
//!
//! [meow-hasher]: https://mollyrocket.com/meowhash
//! [Digest]: https://docs.rs/digest/latest/digest/trait.Digest.html

#![no_std]
#![forbid(rust_2018_idioms)]
#![deny(nonstandard_style)]
#![warn(unreachable_pub, missing_docs)]
#![cfg_attr(target_arch = "aarch64", feature(aarch64_target_feature, stdsimd))]

use core::{
    fmt,
    mem::{self, MaybeUninit},
    sync::atomic::{fence, Ordering},
};
pub use digest;
use digest::generic_array::{
    typenum::{consts::*, Unsigned},
    GenericArray,
};
use digest::Digest;

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
mod x86;
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
use x86::*;

// #[cfg(target_arch = "aarch64")]
// mod arm;
// #[cfg(target_arch = "aarch64")]
// use arm::*;

#[cfg(all(feature = "ffi", any(target_arch = "x86_64", target_arch = "x86")))]
pub mod ffi;

const MEOW_DEFAULT_SEED: [u8; 128] = [
    0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D, 0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34,
    0x4A, 0x40, 0x93, 0x82, 0x22, 0x99, 0xF3, 0x1D, 0x00, 0x82, 0xEF, 0xA9, 0x8E, 0xC4, 0xE6, 0xC8,
    0x94, 0x52, 0x82, 0x1E, 0x63, 0x8D, 0x01, 0x37, 0x7B, 0xE5, 0x46, 0x6C, 0xF3, 0x4E, 0x90, 0xC6,
    0xCC, 0x0A, 0xC2, 0x9B, 0x7C, 0x97, 0xC5, 0x0D, 0xD3, 0xF8, 0x4D, 0x5B, 0x5B, 0x54, 0x70, 0x91,
    0x79, 0x21, 0x6D, 0x5D, 0x98, 0x97, 0x9F, 0xB1, 0xBD, 0x13, 0x10, 0xBA, 0x69, 0x8D, 0xFB, 0x5A,
    0xC2, 0xFF, 0xD7, 0x2D, 0xBD, 0x01, 0xAD, 0xFB, 0x7B, 0x8E, 0x1A, 0xFE, 0xD6, 0xA2, 0x67, 0xE9,
    0x6B, 0xA7, 0xC9, 0x04, 0x5F, 0x12, 0xC7, 0xF9, 0x92, 0x4A, 0x19, 0x94, 0x7B, 0x39, 0x16, 0xCF,
    0x70, 0x80, 0x1F, 0x2E, 0x28, 0x58, 0xEF, 0xC1, 0x66, 0x36, 0x92, 0x0D, 0x87, 0x15, 0x74, 0xE6,
];

const MEOW_MASK_LEN: [u8; 32] = [
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

macro_rules! mix_reg {
    ($r1:ident, $r2:ident, $r3:ident, $r4:ident, $r5:ident, $i1:expr, $i2:expr, $i3:expr, $i4:expr) => {
        $r1 = aesdec($r1, $r2);
        fence(Ordering::AcqRel);
        $r3 = paddq($r3, $i1);
        $r2 = pxor($r2, $i2);
        $r2 = aesdec($r2, $r4);
        fence(Ordering::AcqRel);
        $r5 = paddq($r5, $i3);
        $r4 = pxor($r4, $i4);
    };
}

macro_rules! mix {
    ($r1:ident, $r2:ident, $r3:ident, $r4:ident, $r5:ident, $ptr:expr) => {
        mix_reg!(
            $r1,
            $r2,
            $r3,
            $r4,
            $r5,
            movdqu(($ptr).add(15).cast()),
            movdqu(($ptr).add(0).cast()),
            movdqu(($ptr).add(1).cast()),
            movdqu(($ptr).add(16).cast())
        )
    };
}

macro_rules! shuffle {
    ($r1:ident, $r2:ident, $r3:ident, $r4:ident, $r5:ident, $r6:ident) => {
        $r1 = aesdec($r1, $r4);
        $r2 = paddq($r2, $r5);
        $r4 = pxor($r4, $r6);
        $r4 = aesdec($r4, $r2);
        $r5 = paddq($r5, $r6);
        $r2 = pxor($r2, $r3);
    };
}

/// A hash produced by the `MeowHasher`.
///
/// It consists of 8 128-bit SIMD register values, 128 bytes in total.
/// You can distill it into a `u128` or use the entire 128 byte hash.
///
/// It's recommended to keep the `MeowHash` instead of converting it
/// into an array of bytes, because `MeowHash`es can be compared
/// efficiently using SIMD instructions where byte arrays may need a
/// byte by byte comparison.
#[derive(Clone, Copy)]
pub struct MeowHash {
    regs: [Simd128; 8],
}

impl MeowHash {
    /// Create a `MeowHash` from an array of 128 bytes.
    pub fn from_bytes(bytes: [u8; 128]) -> Self {
        unsafe { mem::transmute(bytes) }
    }

    /// Attempt to construct a `MeowHash` from a slice of bytes.
    ///
    /// This will fail if the slice doesn't contain exactly 128 bytes.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != mem::size_of::<Self>() {
            None
        } else {
            Some(unsafe {
                let mut out = MaybeUninit::<MeowHash>::uninit();
                out.as_mut_ptr()
                    .cast::<u8>()
                    .copy_from_nonoverlapping(bytes.as_ptr(), bytes.len());
                out.assume_init()
            })
        }
    }

    /// Convert a `MeowHash` into an array of 128 bytes.
    pub fn into_bytes(self) -> [u8; 128] {
        unsafe { mem::transmute(self) }
    }

    /// Compress a `MeowHash` into a `u128`.
    pub fn as_u128(&self) -> u128 {
        unsafe {
            let mut xmm0 = paddq(self.regs[0], self.regs[2]);
            let xmm1 = paddq(self.regs[1], self.regs[3]);
            let mut xmm4 = paddq(self.regs[4], self.regs[6]);
            let xmm5 = paddq(self.regs[5], self.regs[7]);
            xmm0 = pxor(xmm0, xmm1);
            xmm4 = pxor(xmm4, xmm5);
            xmm0 = paddq(xmm0, xmm4);
            mem::transmute(xmm0)
        }
    }

    /// Construct a seed value from arbitrary length input data.
    ///
    /// This can be an expensive operation, so try to only do it once.
    pub fn expand_seed(seed: &[u8]) -> Self {
        let mut hasher = MeowHasher::new();
        let ingest_count = (256 / seed.len()) + 2;
        // Would have preferred this to use to_be_bytes() to be stable across platforms,
        // but the reference impl doesn't do this, so we try to stay compatible.
        hasher.update((seed.len() as u64).to_ne_bytes());
        for _ in 0..ingest_count {
            hasher.update(seed);
        }
        hasher.finalise()
    }

    /// Create a `MeowHash` containing the default seed (an encoding of pi).
    pub fn default_seed() -> Self {
        Self::from_bytes(MEOW_DEFAULT_SEED)
    }
}

impl Eq for MeowHash {}
impl PartialEq for MeowHash {
    fn eq(&self, other: &Self) -> bool {
        unsafe {
            cmpeq(self.regs[0], other.regs[0])
                && cmpeq(self.regs[1], other.regs[1])
                && cmpeq(self.regs[2], other.regs[2])
                && cmpeq(self.regs[3], other.regs[3])
                && cmpeq(self.regs[4], other.regs[4])
                && cmpeq(self.regs[5], other.regs[5])
                && cmpeq(self.regs[6], other.regs[6])
                && cmpeq(self.regs[7], other.regs[7])
        }
    }
}

impl Into<u128> for MeowHash {
    fn into(self) -> u128 {
        self.as_u128()
    }
}

impl From<[u8; 128]> for MeowHash {
    fn from(bytes: [u8; 128]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl Into<[u8; 128]> for MeowHash {
    fn into(self) -> [u8; 128] {
        self.into_bytes()
    }
}

impl From<GenericArray<u8, U128>> for MeowHash {
    fn from(array: GenericArray<u8, U128>) -> Self {
        Self::from_bytes(unsafe { mem::transmute(array) })
    }
}

impl Into<GenericArray<u8, U128>> for MeowHash {
    fn into(self) -> GenericArray<u8, U128> {
        unsafe { mem::transmute(self) }
    }
}

impl fmt::Debug for MeowHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        // for byte in self.into_bytes().iter() {
        //     write!(f, "{:X}", byte)?;
        // }
        // Ok(())
        self.into_bytes().fmt(f)
    }
}

const MEOW_BUFFER_SIZE: usize = 256;
const MEOW_BUFFER_PADDING: usize = 32;

/// Meow hasher.
///
/// An implementation of the [Meow hasher][meow-hasher] providing the
/// [Digest][Digest] trait.
///
/// [meow-hasher]: https://mollyrocket.com/meowhash
/// [Digest]: https://docs.rs/digest/latest/digest/trait.Digest.html
pub struct MeowHasher {
    state: MeowHash,
    total: usize,
    buffer_len: usize,
    buffer: [u8; MEOW_BUFFER_SIZE + MEOW_BUFFER_PADDING],
}

impl MeowHasher {
    /// Compute the hash of a chunk of data using the provided seed.
    #[inline]
    pub fn hash_with_seed(seed: MeowHash, data: &[u8]) -> MeowHash {
        Self::with_seed(seed).chain(data).finalise()
    }

    /// Compute the hash of a chunk of data.
    #[inline]
    pub fn hash(data: &[u8]) -> MeowHash {
        Self::new().chain(data).finalise()
    }

    /// Create a new hasher instance with the provided seed.
    pub fn with_seed(seed: MeowHash) -> Self {
        Self {
            state: seed,
            total: 0,
            buffer_len: 0,
            buffer: [0; MEOW_BUFFER_SIZE + MEOW_BUFFER_PADDING],
        }
    }

    /// Produce a hash from the input data.
    pub fn finalise(&mut self) -> MeowHash {
        unsafe { self.cleanup() };
        self.state
    }

    /// Compute the hash of a chunk of data using the provided seed.
    ///
    /// This returns a `GenericArray<u8, U128>` instead of a `MeowHash`, and
    /// mirrors `Digest::digest()`.
    #[inline]
    pub fn digest_with_seed(seed: MeowHash, bytes: &[u8]) -> GenericArray<u8, U128> {
        Self::hash_with_seed(seed, bytes).into()
    }

    unsafe fn absorb_blocks(&mut self, mut block_count: usize, mut rax: *const u8) {
        let mut xmm0 = movdqu(&self.state.regs[0] as *const _ as *const u8);
        let mut xmm1 = movdqu(&self.state.regs[1] as *const _ as *const u8);
        let mut xmm2 = movdqu(&self.state.regs[2] as *const _ as *const u8);
        let mut xmm3 = movdqu(&self.state.regs[3] as *const _ as *const u8);
        let mut xmm4 = movdqu(&self.state.regs[4] as *const _ as *const u8);
        let mut xmm5 = movdqu(&self.state.regs[5] as *const _ as *const u8);
        let mut xmm6 = movdqu(&self.state.regs[6] as *const _ as *const u8);
        let mut xmm7 = movdqu(&self.state.regs[7] as *const _ as *const u8);

        if block_count > MEOW_PREFETCH_LIMIT {
            while block_count > 0 {
                prefetcht0(rax.add(MEOW_PREFETCH));
                prefetcht0(rax.add(MEOW_PREFETCH + 0x40));
                prefetcht0(rax.add(MEOW_PREFETCH + 0x80));
                prefetcht0(rax.add(MEOW_PREFETCH + 0xC0));

                mix!(xmm0, xmm4, xmm6, xmm1, xmm2, rax.add(0x00));
                mix!(xmm1, xmm5, xmm7, xmm2, xmm3, rax.add(0x20));
                mix!(xmm2, xmm6, xmm0, xmm3, xmm4, rax.add(0x40));
                mix!(xmm3, xmm7, xmm1, xmm4, xmm5, rax.add(0x60));
                mix!(xmm4, xmm0, xmm2, xmm5, xmm6, rax.add(0x80));
                mix!(xmm5, xmm1, xmm3, xmm6, xmm7, rax.add(0xa0));
                mix!(xmm6, xmm2, xmm4, xmm7, xmm0, rax.add(0xc0));
                mix!(xmm7, xmm3, xmm5, xmm0, xmm1, rax.add(0xe0));

                rax = rax.add(0x100);

                block_count -= 1;
            }
        } else {
            while block_count > 0 {
                mix!(xmm0, xmm4, xmm6, xmm1, xmm2, rax.add(0x00));
                mix!(xmm1, xmm5, xmm7, xmm2, xmm3, rax.add(0x20));
                mix!(xmm2, xmm6, xmm0, xmm3, xmm4, rax.add(0x40));
                mix!(xmm3, xmm7, xmm1, xmm4, xmm5, rax.add(0x60));
                mix!(xmm4, xmm0, xmm2, xmm5, xmm6, rax.add(0x80));
                mix!(xmm5, xmm1, xmm3, xmm6, xmm7, rax.add(0xa0));
                mix!(xmm6, xmm2, xmm4, xmm7, xmm0, rax.add(0xc0));
                mix!(xmm7, xmm3, xmm5, xmm0, xmm1, rax.add(0xe0));

                rax = rax.add(0x100);

                block_count -= 1;
            }
        }

        movdqu_mem(&mut self.state.regs[0], xmm0);
        movdqu_mem(&mut self.state.regs[1], xmm1);
        movdqu_mem(&mut self.state.regs[2], xmm2);
        movdqu_mem(&mut self.state.regs[3], xmm3);
        movdqu_mem(&mut self.state.regs[4], xmm4);
        movdqu_mem(&mut self.state.regs[5], xmm5);
        movdqu_mem(&mut self.state.regs[6], xmm6);
        movdqu_mem(&mut self.state.regs[7], xmm7);
    }

    unsafe fn absorb(&mut self, data: &[u8]) {
        let mut len = data.len();
        self.total += len;
        let mut source = data.as_ptr();

        if self.buffer_len != 0 {
            let fill = (MEOW_BUFFER_SIZE - self.buffer_len).min(len);
            len -= fill;
            self.buffer
                .as_mut_ptr()
                .add(self.buffer_len)
                .copy_from_nonoverlapping(source, fill);
            source = source.add(fill);
            self.buffer_len += fill;

            if self.buffer_len == MEOW_BUFFER_SIZE {
                self.absorb_blocks(1, self.buffer.as_ptr());
                self.buffer_len = 0;
            }
        }

        let block_count = len >> 8;
        let advance = block_count << 8;
        self.absorb_blocks(block_count, source);

        len -= advance;
        source = source.add(advance);

        self.buffer
            .as_mut_ptr()
            .add(self.buffer_len)
            .copy_from_nonoverlapping(source, len);
        self.buffer_len += len;
    }

    unsafe fn cleanup(&mut self) {
        let len = self.total;
        let rax = self.buffer.as_ptr();

        let mut xmm0 = movdqu(&self.state.regs[0] as *const _ as *const u8);
        let mut xmm1 = movdqu(&self.state.regs[1] as *const _ as *const u8);
        let mut xmm2 = movdqu(&self.state.regs[2] as *const _ as *const u8);
        let mut xmm3 = movdqu(&self.state.regs[3] as *const _ as *const u8);
        let mut xmm4 = movdqu(&self.state.regs[4] as *const _ as *const u8);
        let mut xmm5 = movdqu(&self.state.regs[5] as *const _ as *const u8);
        let mut xmm6 = movdqu(&self.state.regs[6] as *const _ as *const u8);
        let mut xmm7 = movdqu(&self.state.regs[7] as *const _ as *const u8);
        let mut xmm8;
        let mut xmm9;
        let mut xmm10;
        let mut xmm11;
        let mut xmm12;
        let xmm13;
        let mut xmm14;
        let xmm15;

        xmm9 = pxor_clear();
        xmm11 = pxor_clear();

        let last = rax.add(len & 0xF0);
        let len8 = len & 0xF;

        if len8 > 0 {
            xmm8 = movdqu(&MEOW_MASK_LEN[0x10 - len8]);
            xmm9 = movdqu(last);
            xmm9 = pand(xmm9, xmm8);
        }

        if len & 0x10 != 0 {
            xmm11 = xmm9;
            xmm9 = movdqu(last.sub(0x10));
        }

        xmm8 = xmm9;
        xmm10 = xmm9;
        xmm8 = palignr_15(xmm8, xmm11);
        xmm10 = palignr_1(xmm10, xmm11);
        xmm12 = pxor_clear();
        xmm13 = pxor_clear();
        xmm14 = pxor_clear();
        xmm15 = movq(len as i64);
        xmm12 = palignr_15(xmm12, xmm15);
        xmm14 = palignr_1(xmm14, xmm15);

        mix_reg!(xmm0, xmm4, xmm6, xmm1, xmm2, xmm8, xmm9, xmm10, xmm11);
        mix_reg!(xmm1, xmm5, xmm7, xmm2, xmm3, xmm12, xmm13, xmm14, xmm15);

        let mut lane_count = (len >> 5) & 0x7;
        if lane_count != 0 {
            mix!(xmm2, xmm6, xmm0, xmm3, xmm4, rax.add(0x00));
            lane_count -= 1;
            if lane_count != 0 {
                mix!(xmm3, xmm7, xmm1, xmm4, xmm5, rax.add(0x20));
                lane_count -= 1;
                if lane_count != 0 {
                    mix!(xmm4, xmm0, xmm2, xmm5, xmm6, rax.add(0x40));
                    lane_count -= 1;
                    if lane_count != 0 {
                        mix!(xmm5, xmm1, xmm3, xmm6, xmm7, rax.add(0x60));
                        lane_count -= 1;
                        if lane_count != 0 {
                            mix!(xmm6, xmm2, xmm4, xmm7, xmm0, rax.add(0x80));
                            lane_count -= 1;
                            if lane_count != 0 {
                                mix!(xmm7, xmm3, xmm5, xmm0, xmm1, rax.add(0xa0));
                                lane_count -= 1;
                                if lane_count != 0 {
                                    mix!(xmm0, xmm4, xmm6, xmm1, xmm2, rax.add(0xc0));
                                }
                            }
                        }
                    }
                }
            }
        }

        shuffle!(xmm0, xmm1, xmm2, xmm4, xmm5, xmm6);
        shuffle!(xmm1, xmm2, xmm3, xmm5, xmm6, xmm7);
        shuffle!(xmm2, xmm3, xmm4, xmm6, xmm7, xmm0);
        shuffle!(xmm3, xmm4, xmm5, xmm7, xmm0, xmm1);
        shuffle!(xmm4, xmm5, xmm6, xmm0, xmm1, xmm2);
        shuffle!(xmm5, xmm6, xmm7, xmm1, xmm2, xmm3);
        shuffle!(xmm6, xmm7, xmm0, xmm2, xmm3, xmm4);
        shuffle!(xmm7, xmm0, xmm1, xmm3, xmm4, xmm5);
        shuffle!(xmm0, xmm1, xmm2, xmm4, xmm5, xmm6);
        shuffle!(xmm1, xmm2, xmm3, xmm5, xmm6, xmm7);
        shuffle!(xmm2, xmm3, xmm4, xmm6, xmm7, xmm0);
        shuffle!(xmm3, xmm4, xmm5, xmm7, xmm0, xmm1);

        movdqu_mem(&mut self.state.regs[0], xmm0);
        movdqu_mem(&mut self.state.regs[1], xmm1);
        movdqu_mem(&mut self.state.regs[2], xmm2);
        movdqu_mem(&mut self.state.regs[3], xmm3);
        movdqu_mem(&mut self.state.regs[4], xmm4);
        movdqu_mem(&mut self.state.regs[5], xmm5);
        movdqu_mem(&mut self.state.regs[6], xmm6);
        movdqu_mem(&mut self.state.regs[7], xmm7);
    }
}

impl Digest for MeowHasher {
    type OutputSize = U128;

    fn new() -> Self {
        Self::with_seed(MeowHash::default_seed())
    }

    fn update(&mut self, bytes: impl AsRef<[u8]>) {
        unsafe { self.absorb(bytes.as_ref()) }
    }

    fn chain(mut self, bytes: impl AsRef<[u8]>) -> Self {
        self.update(bytes);
        self
    }

    fn finalize(mut self) -> GenericArray<u8, Self::OutputSize> {
        unsafe { self.cleanup() };
        self.state.into()
    }

    fn finalize_reset(&mut self) -> GenericArray<u8, Self::OutputSize> {
        unsafe { self.cleanup() };
        let hash = self.state.into();
        self.reset();
        hash
    }

    fn reset(&mut self) {
        *self = Self::new();
    }

    fn output_size() -> usize {
        Self::OutputSize::USIZE
    }

    fn digest(bytes: &[u8]) -> GenericArray<u8, Self::OutputSize> {
        Self::hash(bytes).into()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::collection::vec;
    use proptest::num::{u8, usize};
    use proptest::proptest;

    #[test]
    fn reference_data() {
        let expected = MeowHash::from_bytes([
            239, 252, 31, 97, 145, 16, 231, 224, 114, 155, 243, 232, 106, 160, 174, 227, 253, 227,
            225, 40, 155, 19, 148, 247, 21, 242, 224, 185, 91, 249, 186, 66, 179, 15, 65, 71, 206,
            151, 157, 13, 168, 148, 184, 124, 94, 116, 223, 149, 62, 143, 81, 207, 230, 89, 19, 97,
            178, 53, 208, 142, 92, 147, 129, 217, 144, 30, 63, 243, 249, 55, 135, 7, 172, 123, 24,
            109, 16, 134, 239, 178, 98, 196, 181, 44, 215, 230, 95, 179, 212, 194, 113, 101, 53,
            112, 169, 247, 17, 12, 126, 97, 121, 69, 153, 161, 169, 128, 94, 95, 26, 157, 146, 145,
            93, 120, 146, 83, 84, 204, 246, 126, 143, 235, 134, 82, 169, 160, 120, 163,
        ]);
        let doge = include_bytes!("../test/follow-your-dreams.jpg");
        let hash = MeowHasher::hash(doge);
        assert_eq!(hash, expected);

        #[cfg(all(feature = "ffi", any(target_arch = "x86_64", target_arch = "x86")))]
        {
            let hash2 = ffi::CMeowHasher::hash(doge);
            assert_eq!(hash2, expected);
        }
    }

    proptest! {
        #[test]
        fn hash_same_data(seed in vec(u8::ANY, 128), blob in vec(u8::ANY, 0..65536)) {
            let seed = MeowHash::from_slice(&seed).unwrap();
            let mut hasher = MeowHasher::with_seed(seed);
            hasher.update(&blob);
            let hash1 = hasher.finalise();
            let hash2 = MeowHasher::hash_with_seed(seed, &blob);
            // Two hashes of the same data are equal
            assert_eq!(hash1, hash2);
        }

        #[test]
        fn hash_different_seeds(mut seed in vec(u8::ANY, 128), blob in vec(u8::ANY, 0..65536)) {
            let seed1 = MeowHash::from_slice(&seed).unwrap();
            let hash1 = MeowHasher::hash_with_seed(seed1, &blob);
            seed[0] ^= 0xFF;
            let seed2 = MeowHash::from_slice(&seed).unwrap();
            let hash2 = MeowHasher::hash_with_seed(seed2, &blob);
            // Hashes with different seeds are not equal
            assert_ne!(hash1, hash2);
        }

        #[test]
        fn hash_different_data(mut blob in vec(u8::ANY, 1..65536), modify in usize::ANY) {
            let hash1 = MeowHasher::hash(&blob);
            let modify = modify % blob.len();
            blob[modify] ^= 1;
            let hash2 = MeowHasher::hash(&blob);
            // A blob with one bit modified hashes differently
            assert_ne!(hash1, hash2);
        }

        #[cfg(all(feature = "ffi", any(target_arch = "x86_64", target_arch = "x86")))]
        #[test]
        fn compare_with_ffi(source in vec(u8::ANY, 1..65536)) {
            let hash1 = MeowHasher::hash(&source);
            let hash2 = ffi::CMeowHasher::hash(&source);
            // Ensure we hash the same as upstream
            assert_eq!(hash1, hash2);
        }
    }
}
