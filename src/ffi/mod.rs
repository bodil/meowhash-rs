// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! FFI bindings for the original C version of MeowHash.

use crate::{MeowHash, MEOW_DEFAULT_SEED};
use core::mem::MaybeUninit;

type CMeowState = *mut libc::c_void;

extern "C" {
    fn meow_begin(seed128: *const u8) -> CMeowState;
    fn meow_free(state: CMeowState);
    fn meow_absorb(state: CMeowState, len: usize, source: *const libc::c_void);
    fn meow_end(state: CMeowState, store: *mut u8);
}

/// A hasher using the original C implementation of MeowHash.
pub struct CMeowHasher(CMeowState);

impl CMeowHasher {
    /// Construct a new hasher.
    pub fn new() -> Self {
        let state = unsafe { meow_begin(MEOW_DEFAULT_SEED.as_ptr()) };
        if state.is_null() {
            panic!("failed to allocate meow_state");
        }
        CMeowHasher(state)
    }

    /// Feed the hasher data.
    pub fn absorb(&mut self, data: &[u8]) {
        unsafe { meow_absorb(self.0, data.len(), data.as_ptr().cast()) }
    }

    /// Finalise the hasher and get the hashed result.
    pub fn end(&mut self) -> MeowHash {
        let mut hash = MaybeUninit::<MeowHash>::zeroed();
        unsafe {
            meow_end(self.0, hash.as_mut_ptr().cast());
            hash.assume_init()
        }
    }

    /// Hash some data directly.
    pub fn hash(data: &[u8]) -> MeowHash {
        let mut hasher = Self::new();
        hasher.absorb(data);
        hasher.end()
    }
}

impl Drop for CMeowHasher {
    fn drop(&mut self) {
        unsafe { meow_free(self.0) }
    }
}

impl Default for CMeowHasher {
    fn default() -> Self {
        Self::new()
    }
}
