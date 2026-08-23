# Changelog

## [0.7.0](https://github.com/mathematic-inc/protovalidate-buffa/compare/protoc-gen-protovalidate-buffa-v0.6.0...protoc-gen-protovalidate-buffa-v0.7.0) (2026-08-23)


### ⚠ BREAKING CHANGES

* update dependencies to latest ([#23](https://github.com/mathematic-inc/protovalidate-buffa/issues/23))
* consolidate keyword, connectrpc, and buffa fixes ([#17](https://github.com/mathematic-inc/protovalidate-buffa/issues/17))
* update buffa to 0.6 and connectrpc to 0.6.
* compile-time expansion of CEL rules; drop runtime interpreter ([#10](https://github.com/mathematic-inc/protovalidate-buffa/issues/10))
* requires Rust 1.95+ and edition 2024; depends on buffa 0.5 (was 0.4) and connectrpc 0.4 (was 0.3).

### Features

* Compile-time expansion of CEL rules; drop runtime interpreter ([#10](https://github.com/mathematic-inc/protovalidate-buffa/issues/10)) ([929766a](https://github.com/mathematic-inc/protovalidate-buffa/commit/929766a92e0d642f8fc624ae1f05508affbba350))
* Complete protovalidate coverage ([c18b413](https://github.com/mathematic-inc/protovalidate-buffa/commit/c18b413393dc24fe64e0fbc911d3a93ad007453a))
* Initial commit ([7fedb7d](https://github.com/mathematic-inc/protovalidate-buffa/commit/7fedb7d9cf5f3bb0586e190be565f400fe442edc))


### Bug Fixes

* Borrow value in optional string pattern check ([#21](https://github.com/mathematic-inc/protovalidate-buffa/issues/21)) ([9ce6eff](https://github.com/mathematic-inc/protovalidate-buffa/commit/9ce6effa4a3cce10488169f95daf54c92a0baac1))
* Bump buffa to 0.5.2, update edition to 2024, all deps to latest ([#4](https://github.com/mathematic-inc/protovalidate-buffa/issues/4)) ([03de1bb](https://github.com/mathematic-inc/protovalidate-buffa/commit/03de1bbb3821d8bf88b57e76efe198d54ceca93e))
* Consolidate keyword, connectrpc, and buffa fixes ([#17](https://github.com/mathematic-inc/protovalidate-buffa/issues/17)) ([4881a4f](https://github.com/mathematic-inc/protovalidate-buffa/commit/4881a4fa07f24be153fb7157fd3cbd37c76c6110))
* Match buffa's `*Oneof` enum naming ([dd5371d](https://github.com/mathematic-inc/protovalidate-buffa/commit/dd5371d17f6fbd79fda14a301c72ea034920c873))
* Publish protovalidate-buffa-protos v0.1.1 with buffa 0.4 ([2c8e53d](https://github.com/mathematic-inc/protovalidate-buffa/commit/2c8e53d51e3e4e3ec4981cafd5a79a0b6e7cc542))


### Build System

* Update dependencies to latest ([2a35114](https://github.com/mathematic-inc/protovalidate-buffa/commit/2a351141874dcac50437b8e1017fa47eb8f840c0))
* Update dependencies to latest ([#23](https://github.com/mathematic-inc/protovalidate-buffa/issues/23)) ([52b7333](https://github.com/mathematic-inc/protovalidate-buffa/commit/52b733378bc8b71f96b5dba30483c69c0949a4fa))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * protovalidate-buffa-protos bumped from 0.6.0 to 0.7.0

## [0.6.0](https://github.com/mathematic-inc/protovalidate-buffa/compare/protoc-gen-protovalidate-buffa-v0.5.1...protoc-gen-protovalidate-buffa-v0.6.0) (2026-07-25)


### ⚠ BREAKING CHANGES

* update dependencies to latest ([#23](https://github.com/mathematic-inc/protovalidate-buffa/issues/23))

### Build System

* Update dependencies to latest ([#23](https://github.com/mathematic-inc/protovalidate-buffa/issues/23)) ([7728378](https://github.com/mathematic-inc/protovalidate-buffa/commit/772837810c129a3acb9166973c40e7696866cdc9))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * protovalidate-buffa-protos bumped from 0.5.0 to 0.6.0

## [0.5.1](https://github.com/mathematic-inc/protovalidate-buffa/compare/protoc-gen-protovalidate-buffa-v0.5.0...protoc-gen-protovalidate-buffa-v0.5.1) (2026-07-14)


### Bug Fixes

* Borrow value in optional string pattern check ([#21](https://github.com/mathematic-inc/protovalidate-buffa/issues/21)) ([5e58b3d](https://github.com/mathematic-inc/protovalidate-buffa/commit/5e58b3d51da60cee6a7f93d65028cf4428cc1e91))

## [0.5.0](https://github.com/mathematic-inc/protovalidate-buffa/compare/protoc-gen-protovalidate-buffa-v0.4.0...protoc-gen-protovalidate-buffa-v0.5.0) (2026-06-28)


### ⚠ BREAKING CHANGES

* consolidate keyword, connectrpc, and buffa fixes ([#17](https://github.com/mathematic-inc/protovalidate-buffa/issues/17))

### Bug Fixes

* Consolidate keyword, connectrpc, and buffa fixes ([#17](https://github.com/mathematic-inc/protovalidate-buffa/issues/17)) ([61b2485](https://github.com/mathematic-inc/protovalidate-buffa/commit/61b2485d09a99d272e354b04111e1568479b531d))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * protovalidate-buffa-protos bumped from 0.4.0 to 0.5.0

## [0.4.0](https://github.com/mathematic-inc/protovalidate-buffa/compare/protoc-gen-protovalidate-buffa-v0.3.0...protoc-gen-protovalidate-buffa-v0.4.0) (2026-05-25)


### ⚠ BREAKING CHANGES

* update buffa to 0.6 and connectrpc to 0.6.

### Build System

* Update dependencies to latest ([8a186b1](https://github.com/mathematic-inc/protovalidate-buffa/commit/8a186b11faaecd52f0edae2bb6148b4771fd19f2))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * protovalidate-buffa-protos bumped from 0.3.0 to 0.4.0

## [0.3.0](https://github.com/mathematic-inc/protovalidate-buffa/compare/protoc-gen-protovalidate-buffa-v0.2.1...protoc-gen-protovalidate-buffa-v0.3.0) (2026-05-18)


### ⚠ BREAKING CHANGES

* compile-time expansion of CEL rules; drop runtime interpreter ([#10](https://github.com/mathematic-inc/protovalidate-buffa/issues/10))

### Features

* Compile-time expansion of CEL rules; drop runtime interpreter ([#10](https://github.com/mathematic-inc/protovalidate-buffa/issues/10)) ([ba01ffe](https://github.com/mathematic-inc/protovalidate-buffa/commit/ba01ffe75b6da086253c8366d266fbbd12c55e30))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * protovalidate-buffa-protos bumped from 0.2.0 to 0.3.0

## [0.2.1](https://github.com/mathematic-inc/protovalidate-buffa/compare/protoc-gen-protovalidate-buffa-v0.2.0...protoc-gen-protovalidate-buffa-v0.2.1) (2026-05-16)


### Features

* Complete protovalidate coverage ([bbe9772](https://github.com/mathematic-inc/protovalidate-buffa/commit/bbe977247acd9afdc6c23c6e8c3be4bcdb12e114))

## [0.2.0](https://github.com/mathematic-inc/protovalidate-buffa/compare/protoc-gen-protovalidate-buffa-v0.1.2...protoc-gen-protovalidate-buffa-v0.2.0) (2026-05-09)


### ⚠ BREAKING CHANGES

* requires Rust 1.95+ and edition 2024; depends on buffa 0.5 (was 0.4) and connectrpc 0.4 (was 0.3).

### Bug Fixes

* Bump buffa to 0.5.2, update edition to 2024, all deps to latest ([#4](https://github.com/mathematic-inc/protovalidate-buffa/issues/4)) ([743de86](https://github.com/mathematic-inc/protovalidate-buffa/commit/743de8677046d84deb2383bf453f1e62fbc195db))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * protovalidate-buffa-protos bumped from 0.1.2 to 0.2.0

## [0.1.2](https://github.com/mathematic-inc/protovalidate-buffa/compare/protoc-gen-protovalidate-buffa-v0.1.1...protoc-gen-protovalidate-buffa-v0.1.2) (2026-04-28)


### Bug Fixes

* Publish protovalidate-buffa-protos v0.1.1 with buffa 0.4 ([a31aff0](https://github.com/mathematic-inc/protovalidate-buffa/commit/a31aff0a91d65acb4c61fb9631ec0874df65e68f))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * protovalidate-buffa-protos bumped from 0.1.1 to 0.1.2

## [0.1.1](https://github.com/mathematic-inc/protovalidate-buffa/compare/protoc-gen-protovalidate-buffa-v0.1.0...protoc-gen-protovalidate-buffa-v0.1.1) (2026-04-28)


### Bug Fixes

* Match buffa's `*Oneof` enum naming ([59b307f](https://github.com/mathematic-inc/protovalidate-buffa/commit/59b307f88b68f10dae6ab7157cc7b28cbda2808d))

## 0.1.0 (2026-04-21)


### Features

* Initial commit ([07b7a65](https://github.com/mathematic-inc/protovalidate-buffa/commit/07b7a65222855cc1f1ce0a6d24a119586d7d7e27))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * protovalidate-buffa-protos bumped from 0.0.0 to 0.1.0
