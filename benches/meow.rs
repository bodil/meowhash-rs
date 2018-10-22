// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#![feature(test)]

extern crate digest;
extern crate meowhash;
extern crate test;

use digest::Digest;
use meowhash::MeowHasher;
use test::Bencher;

fn rand_blob(size: usize) -> Vec<u8> {
    (0..size).map(|v| v as u8).collect()
}

fn hash_n(size: usize, b: &mut Bencher) {
    let blob = rand_blob(size);
    b.iter(|| {
        let mut hasher = MeowHasher::new();
        hasher.input(&blob);
        hasher.result()
    })
}

#[bench]
fn hash_1_16k(b: &mut Bencher) {
    hash_n(16 * 1024, b)
}

#[bench]
fn hash_2_128k(b: &mut Bencher) {
    hash_n(128 * 1024, b)
}

#[bench]
fn hash_3_1m(b: &mut Bencher) {
    hash_n(1024 * 1024, b)
}

#[bench]
fn hash_4_16m(b: &mut Bencher) {
    hash_n(16 * 1024 * 1024, b)
}

#[bench]
fn hash_5_1g(b: &mut Bencher) {
    hash_n(1024 * 1024 * 1024, b)
}

fn digest_n(size: usize, b: &mut Bencher) {
    let blob = rand_blob(size);
    b.iter(|| MeowHasher::digest(&blob))
}

#[bench]
fn digest_1_16k(b: &mut Bencher) {
    digest_n(16 * 1024, b)
}

#[bench]
fn digest_2_128k(b: &mut Bencher) {
    digest_n(128 * 1024, b)
}

#[bench]
fn digest_3_1m(b: &mut Bencher) {
    digest_n(1024 * 1024, b)
}

#[bench]
fn digest_4_16m(b: &mut Bencher) {
    digest_n(16 * 1024 * 1024, b)
}

#[bench]
fn digest_5_1g(b: &mut Bencher) {
    digest_n(1024 * 1024 * 1024, b)
}
