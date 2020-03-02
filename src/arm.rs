// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// This is very slow and also incorrect in places. The hashing seems to
// have the expected properties but isn't consistent with x86, giving
// different hash results. It's nearly an order of magnitude slower than
// x86, because so many SIMD instructions are absent. Because of this,
// aarch64 support has been disabled as of version 0.2.
//
// If you can fix it, go for it.

use core::arch::aarch64::*;

pub(crate) type Simd128 = uint8x16_t;

pub(crate) const MEOW_PREFETCH: usize = 0;
pub(crate) const MEOW_PREFETCH_LIMIT: usize = 0;

#[inline]
pub(crate) unsafe fn prefetcht0(_p: *const u8) {}

#[inline]
pub(crate) unsafe fn movdqu(addr: *const u8) -> Simd128 {
    *(addr.cast::<Simd128>())
}

#[inline]
pub(crate) unsafe fn movdqu_mem(addr: *mut Simd128, value: Simd128) {
    *addr = value;
}

#[inline]
pub(crate) unsafe fn movq(value: i64) -> Simd128 {
    let values = [0, value];
    movdqu(values.as_ptr().cast())
}

#[inline]
#[target_feature(enable = "crypto")]
pub(crate) unsafe fn aesdec(value: Simd128, key: Simd128) -> Simd128 {
    vaesdq_u8(value, key)
}

#[inline]
pub(crate) unsafe fn pxor(a: Simd128, b: Simd128) -> Simd128 {
    let a: u128 = core::mem::transmute(a);
    let b: u128 = core::mem::transmute(b);
    core::mem::transmute(a ^ b)
}

#[inline]
#[target_feature(enable = "neon")]
pub(crate) unsafe fn paddq(a: Simd128, b: Simd128) -> Simd128 {
    core::mem::transmute(vaddq_u64(core::mem::transmute(a), core::mem::transmute(b)))
}

#[inline]
pub(crate) unsafe fn pand(a: Simd128, b: Simd128) -> Simd128 {
    let a: u128 = core::mem::transmute(a);
    let b: u128 = core::mem::transmute(b);
    core::mem::transmute(a & b)
}

#[inline]
unsafe fn palignr(a: Simd128, b: Simd128, n: usize) -> Simd128 {
    let concat = [a, b];
    movdqu(concat.as_ptr().cast::<u8>().add(16 - n))
}

#[inline]
pub(crate) unsafe fn palignr_1(a: Simd128, b: Simd128) -> Simd128 {
    palignr(a, b, 1)
}

#[inline]
pub(crate) unsafe fn palignr_15(a: Simd128, b: Simd128) -> Simd128 {
    palignr(a, b, 15)
}

#[inline]
pub(crate) unsafe fn pxor_clear() -> Simd128 {
    core::mem::transmute(0u128)
}

#[inline]
pub(crate) unsafe fn cmpeq(a: Simd128, b: Simd128) -> bool {
    let a: u128 = core::mem::transmute(a);
    let b: u128 = core::mem::transmute(b);
    a == b
}
