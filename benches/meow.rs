// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

extern crate digest;
extern crate meowhash;

use digest::Digest;
use meowhash::MeowHasher;
use bencher::{Bencher, benchmark_group, benchmark_main};

fn rand_blob(size: usize) -> Vec<u8> {
    (0..size).map(|v| v as u8).collect()
}

fn hash_n(size: usize, b: &mut Bencher) {
    let blob = rand_blob(size);
    b.iter(|| {
        let mut hasher = MeowHasher::new();
        hasher.update(&blob);
        hasher.finalise()
    })
}

fn hash_1_16k(b: &mut Bencher) {
    hash_n(16 * 1024, b)
}

fn hash_2_128k(b: &mut Bencher) {
    hash_n(128 * 1024, b)
}

fn hash_3_1m(b: &mut Bencher) {
    hash_n(1024 * 1024, b)
}

fn hash_4_16m(b: &mut Bencher) {
    hash_n(16 * 1024 * 1024, b)
}

fn hash_5_1g(b: &mut Bencher) {
    hash_n(1024 * 1024 * 1024, b)
}

fn digest_n(size: usize, b: &mut Bencher) {
    let blob = rand_blob(size);
    b.iter(|| MeowHasher::hash(&blob))
}

fn digest_1_16k(b: &mut Bencher) {
    digest_n(16 * 1024, b)
}

fn digest_2_128k(b: &mut Bencher) {
    digest_n(128 * 1024, b)
}

fn digest_3_1m(b: &mut Bencher) {
    digest_n(1024 * 1024, b)
}

fn digest_4_16m(b: &mut Bencher) {
    digest_n(16 * 1024 * 1024, b)
}

fn digest_5_1g(b: &mut Bencher) {
    digest_n(1024 * 1024 * 1024, b)
}

#[cfg(all(feature = "ffi", any(target_arch = "x86_64", target_arch = "x86")))]
fn ffi_hash_n(size: usize, b: &mut Bencher) {
    let blob = rand_blob(size);
    b.iter(|| {
        let mut hasher = meowhash::ffi::CMeowHasher::new();
        hasher.absorb(&blob);
        hasher.end()
    })
}

#[cfg(all(feature = "ffi", any(target_arch = "x86_64", target_arch = "x86")))]
fn ffi_hash_1_16k(b: &mut Bencher) {
    ffi_hash_n(16 * 1024, b)
}

#[cfg(all(feature = "ffi", any(target_arch = "x86_64", target_arch = "x86")))]
fn ffi_hash_2_128k(b: &mut Bencher) {
    ffi_hash_n(128 * 1024, b)
}

#[cfg(all(feature = "ffi", any(target_arch = "x86_64", target_arch = "x86")))]
fn ffi_hash_3_1m(b: &mut Bencher) {
    ffi_hash_n(1024 * 1024, b)
}

#[cfg(all(feature = "ffi", any(target_arch = "x86_64", target_arch = "x86")))]
fn ffi_hash_4_16m(b: &mut Bencher) {
    ffi_hash_n(16 * 1024 * 1024, b)
}

#[cfg(all(feature = "ffi", any(target_arch = "x86_64", target_arch = "x86")))]
fn ffi_hash_5_1g(b: &mut Bencher) {
    ffi_hash_n(1024 * 1024 * 1024, b)
}

benchmark_group!(hash, hash_1_16k, hash_2_128k, hash_3_1m, hash_4_16m, hash_5_1g);
benchmark_group!(digest, digest_1_16k, digest_2_128k, digest_3_1m, digest_4_16m, digest_5_1g);

#[cfg(not(all(feature = "ffi", any(target_arch = "x86_64", target_arch = "x86"))))]
benchmark_main!(hash, digest);

#[cfg(all(feature = "ffi", any(target_arch = "x86_64", target_arch = "x86")))]
benchmark_group!(ffi_hash, ffi_hash_1_16k, ffi_hash_2_128k, ffi_hash_3_1m, ffi_hash_4_16m, ffi_hash_5_1g);

#[cfg(all(feature = "ffi", any(target_arch = "x86_64", target_arch = "x86")))]
benchmark_main!(hash, digest, ffi_hash);
