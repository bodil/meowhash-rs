// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#[cfg(target_arch = "x86")]
use core::arch::x86::{__m128i, _mm_aesdec_si128};
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{__m128i, _mm_aesdec_si128};

use super::MeowLane;

pub(crate) type Simd128 = __m128i;

#[inline]
#[target_feature(enable = "aes")]
pub(crate) unsafe fn aes_rotate(a: &mut MeowLane, b: &mut MeowLane) {
    a.l0 = _mm_aesdec_si128(a.l0, b.l0);
    a.l1 = _mm_aesdec_si128(a.l1, b.l1);
    a.l2 = _mm_aesdec_si128(a.l2, b.l2);
    a.l3 = _mm_aesdec_si128(a.l3, b.l3);

    let tmp = core::ptr::read(&b.l0);
    core::ptr::copy(&b.l1, &mut b.l0, 3);
    core::ptr::write(&mut b.l3, tmp);
}

#[inline]
#[target_feature(enable = "aes")]
pub(crate) unsafe fn aes_merge(a: &mut MeowLane, b: &MeowLane) {
    a.l0 = _mm_aesdec_si128(a.l0, b.l0);
    a.l1 = _mm_aesdec_si128(a.l1, b.l1);
    a.l2 = _mm_aesdec_si128(a.l2, b.l2);
    a.l3 = _mm_aesdec_si128(a.l3, b.l3);
}
