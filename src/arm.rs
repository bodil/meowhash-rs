// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use super::MeowLane;
use core::arch::aarch64::{uint8x16_t, vaesdq_u8};

pub(crate) type Simd128 = uint8x16_t;

#[inline]
#[target_feature(enable = "crypto")]
pub(crate) unsafe fn aes_rotate(a: &mut MeowLane, b: &mut MeowLane) {
    a.l0 = vaesdq_u8(a.l0, b.l0);
    a.l1 = vaesdq_u8(a.l1, b.l1);
    a.l2 = vaesdq_u8(a.l2, b.l2);
    a.l3 = vaesdq_u8(a.l3, b.l3);

    let tmp = core::ptr::read(&b.l0);
    core::ptr::copy(&b.l1, &mut b.l0, 3);
    core::ptr::write(&mut b.l3, tmp);
}

#[inline]
#[target_feature(enable = "crypto")]
pub(crate) unsafe fn aes_merge(a: &mut MeowLane, b: &MeowLane) {
    a.l0 = vaesdq_u8(a.l0, b.l0);
    a.l1 = vaesdq_u8(a.l1, b.l1);
    a.l2 = vaesdq_u8(a.l2, b.l2);
    a.l3 = vaesdq_u8(a.l3, b.l3);
}
