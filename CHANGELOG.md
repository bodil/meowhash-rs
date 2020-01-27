# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic
Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `x86` and `aarch64` architectures are now supported in addition to `x86_64`,
  although `aarch64` requires a nightly rustc because SIMD instructions on
  `aarch64` are still unstable.

## [0.1.2] - 2018-10-22

### Fixed

- All local function calls in the main loop are now properly inlined.

## [0.1.1] - 2018-10-22

### Fixed

- Performance improvements. (#1, #2)

## [0.1.0] - 2018-10-20

- Initial release.
