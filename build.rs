fn main() {
    #[cfg(feature = "ffi")]
    cc::Build::new()
        .flag("-mavx")
        .flag("-maes")
        .file("src/ffi/meow_hash.c")
        .compile("meow");
}
