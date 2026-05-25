# Changelog

## [0.4.0](https://github.com/mathematic-inc/protovalidate-buffa/compare/v0.3.0...v0.4.0) (2026-05-25)


### ⚠ BREAKING CHANGES

* update buffa to 0.6 and connectrpc to 0.6.

### Build System

* Update dependencies to latest ([8a186b1](https://github.com/mathematic-inc/protovalidate-buffa/commit/8a186b11faaecd52f0edae2bb6148b4771fd19f2))

## [0.3.0](https://github.com/mathematic-inc/protovalidate-buffa/compare/v0.2.2...v0.3.0) (2026-05-18)


### ⚠ BREAKING CHANGES

* compile-time expansion of CEL rules; drop runtime interpreter ([#10](https://github.com/mathematic-inc/protovalidate-buffa/issues/10))

### Features

* Compile-time expansion of CEL rules; drop runtime interpreter ([#10](https://github.com/mathematic-inc/protovalidate-buffa/issues/10)) ([ba01ffe](https://github.com/mathematic-inc/protovalidate-buffa/commit/ba01ffe75b6da086253c8366d266fbbd12c55e30))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * protovalidate-buffa-macros bumped from 0.2.0 to 0.3.0

## [0.2.2](https://github.com/mathematic-inc/protovalidate-buffa/compare/v0.2.1...v0.2.2) (2026-05-16)


### Features

* Complete protovalidate coverage ([bbe9772](https://github.com/mathematic-inc/protovalidate-buffa/commit/bbe977247acd9afdc6c23c6e8c3be4bcdb12e114))

## [0.2.1](https://github.com/mathematic-inc/protovalidate-buffa/compare/v0.2.0...v0.2.1) (2026-05-14)


### Bug Fixes

* Impl AsCelValue for FieldMask, Timestamp, Duration WKTs ([#6](https://github.com/mathematic-inc/protovalidate-buffa/issues/6)) ([c454d46](https://github.com/mathematic-inc/protovalidate-buffa/commit/c454d4679098417a05398ea432fad686ca07318f))

## [0.2.0](https://github.com/mathematic-inc/protovalidate-buffa/compare/v0.1.0...v0.2.0) (2026-05-09)


### ⚠ BREAKING CHANGES

* requires Rust 1.95+ and edition 2024; depends on buffa 0.5 (was 0.4) and connectrpc 0.4 (was 0.3).

### Bug Fixes

* Bump buffa to 0.5.2, update edition to 2024, all deps to latest ([#4](https://github.com/mathematic-inc/protovalidate-buffa/issues/4)) ([743de86](https://github.com/mathematic-inc/protovalidate-buffa/commit/743de8677046d84deb2383bf453f1e62fbc195db))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * protovalidate-buffa-macros bumped from 0.1.0 to 0.2.0

## 0.1.0 (2026-04-21)


### Features

* Initial commit ([07b7a65](https://github.com/mathematic-inc/protovalidate-buffa/commit/07b7a65222855cc1f1ce0a6d24a119586d7d7e27))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * protovalidate-buffa-macros bumped from 0.0.0 to 0.1.0
