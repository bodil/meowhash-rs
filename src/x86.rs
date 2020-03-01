// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

pub(crate) type Simd128 = __m128i;

pub(crate) const MEOW_PREFETCH: usize = 4096;
pub(crate) const MEOW_PREFETCH_LIMIT: usize = 0x3ff;

#[inline]
#[target_feature(enable = "sse")]
pub(crate) unsafe fn prefetcht0(p: *const u8) {
    _mm_prefetch(p as *const i8, _MM_HINT_T0)
}

#[inline]
#[target_feature(enable = "sse2")]
pub(crate) unsafe fn movdqu(addr: *const u8) -> Simd128 {
    _mm_loadu_si128(addr.cast())
}

#[inline]
#[target_feature(enable = "sse2")]
pub(crate) unsafe fn movdqu_mem(addr: *mut Simd128, value: Simd128) {
    _mm_storeu_si128(addr, value)
}

#[inline]
#[target_feature(enable = "sse2")]
pub(crate) unsafe fn movq(value: i64) -> Simd128 {
    _mm_set_epi64x(0, value)
}

#[inline]
#[target_feature(enable = "aes")]
pub(crate) unsafe fn aesdec(value: Simd128, key: Simd128) -> Simd128 {
    _mm_aesdec_si128(value, key)
}

#[inline]
#[target_feature(enable = "sse2")]
pub(crate) unsafe fn pxor(a: Simd128, b: Simd128) -> Simd128 {
    _mm_xor_si128(a, b)
}

#[inline]
#[target_feature(enable = "sse2")]
pub(crate) unsafe fn paddq(a: Simd128, b: Simd128) -> Simd128 {
    _mm_add_epi64(a, b)
}

#[inline]
#[target_feature(enable = "sse2")]
pub(crate) unsafe fn pand(a: Simd128, b: Simd128) -> Simd128 {
    _mm_and_si128(a, b)
}

#[inline]
#[target_feature(enable = "ssse3")]
pub(crate) unsafe fn palignr_1(a: Simd128, b: Simd128) -> Simd128 {
    _mm_alignr_epi8(a, b, 1)
}

#[inline]
#[target_feature(enable = "ssse3")]
pub(crate) unsafe fn palignr_15(a: Simd128, b: Simd128) -> Simd128 {
    _mm_alignr_epi8(a, b, 15)
}

#[inline]
#[target_feature(enable = "sse2")]
pub(crate) unsafe fn pxor_clear() -> Simd128 {
    _mm_setzero_si128()
}

#[inline]
#[target_feature(enable = "sse2")]
pub(crate) unsafe fn cmpeq(a: Simd128, b: Simd128) -> bool {
    _mm_movemask_epi8(_mm_cmpeq_epi8(a, b)) == 0xFFFF
}
