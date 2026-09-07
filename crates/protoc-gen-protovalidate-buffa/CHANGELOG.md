# Changelog

## [0.8.0](https://github.com/mathematic-inc/protovalidate-buffa/compare/protoc-gen-protovalidate-buffa-v0.7.3...protoc-gen-protovalidate-buffa-v0.8.0) (2026-09-07)


### ⚠ BREAKING CHANGES

* update buffa to 0.9.1 and connectrpc to 0.9.0 ([#29](https://github.com/mathematic-inc/protovalidate-buffa/issues/29))
* update dependencies to latest ([#23](https://github.com/mathematic-inc/protovalidate-buffa/issues/23))
* consolidate keyword, connectrpc, and buffa fixes ([#17](https://github.com/mathematic-inc/protovalidate-buffa/issues/17))
* update buffa to 0.6 and connectrpc to 0.6.
* compile-time expansion of CEL rules; drop runtime interpreter ([#10](https://github.com/mathematic-inc/protovalidate-buffa/issues/10))
* requires Rust 1.95+ and edition 2024; depends on buffa 0.5 (was 0.4) and connectrpc 0.4 (was 0.3).

### Features

* Align validation errors and enum rules with Protovalidate ([#50](https://github.com/mathematic-inc/protovalidate-buffa/issues/50)) ([85e1b71](https://github.com/mathematic-inc/protovalidate-buffa/commit/85e1b71996d2f7029750f9bfd6cce9d2b98c4742))
* Compile-time expansion of CEL rules; drop runtime interpreter ([#10](https://github.com/mathematic-inc/protovalidate-buffa/issues/10)) ([9151180](https://github.com/mathematic-inc/protovalidate-buffa/commit/91511800894cf440eb0bacbcd1fab4f1ed307520))
* Complete protovalidate coverage ([59d6395](https://github.com/mathematic-inc/protovalidate-buffa/commit/59d6395b9eddabb08ad0ac29f46dd129a6c101e9))
* Initial commit ([b68e578](https://github.com/mathematic-inc/protovalidate-buffa/commit/b68e57853813188c2525ecfcc774a704422be301))
* Validate buffa view types ([#34](https://github.com/mathematic-inc/protovalidate-buffa/issues/34)) ([bccef64](https://github.com/mathematic-inc/protovalidate-buffa/commit/bccef64f99e22586a4f9a89b6eb87b5ce914784f))


### Bug Fixes

* Borrow value in optional string pattern check ([#21](https://github.com/mathematic-inc/protovalidate-buffa/issues/21)) ([8567cec](https://github.com/mathematic-inc/protovalidate-buffa/commit/8567cec7ec89a008fd36354ab7262bae193b7878))
* Bump buffa to 0.5.2, update edition to 2024, all deps to latest ([#4](https://github.com/mathematic-inc/protovalidate-buffa/issues/4)) ([56592ff](https://github.com/mathematic-inc/protovalidate-buffa/commit/56592ffda3afa51a8fec30d4cfb28344e2150b5e))
* **cel:** Preserve oneof presence semantics ([#49](https://github.com/mathematic-inc/protovalidate-buffa/issues/49)) ([7d4d493](https://github.com/mathematic-inc/protovalidate-buffa/commit/7d4d493550fb2827f62aef09e77e246e68a988e0))
* **cel:** Preserve timestamp and duration values across bindings ([#45](https://github.com/mathematic-inc/protovalidate-buffa/issues/45)) ([94037da](https://github.com/mathematic-inc/protovalidate-buffa/commit/94037dafc3016f0c21eb13f68240d57011991614))
* **cel:** Read protobuf defaults for unset message fields ([#47](https://github.com/mathematic-inc/protovalidate-buffa/issues/47)) ([32742d4](https://github.com/mathematic-inc/protovalidate-buffa/commit/32742d49bda94fde507bc27fe8bed2d7fa578b1d))
* Consolidate keyword, connectrpc, and buffa fixes ([#17](https://github.com/mathematic-inc/protovalidate-buffa/issues/17)) ([4e9f4d8](https://github.com/mathematic-inc/protovalidate-buffa/commit/4e9f4d8c65323043ce3866c3dce575e2441043e3))
* **generator:** Use generic package examples ([#40](https://github.com/mathematic-inc/protovalidate-buffa/issues/40)) ([32f5ae1](https://github.com/mathematic-inc/protovalidate-buffa/commit/32f5ae16d7da9ccbce7b210e3e12389683599b25))
* Match buffa's `*Oneof` enum naming ([cccfb04](https://github.com/mathematic-inc/protovalidate-buffa/commit/cccfb0466b5c7aa494d0c9c44fcf08d34f817146))
* Publish protovalidate-buffa-protos v0.1.1 with buffa 0.4 ([1891db1](https://github.com/mathematic-inc/protovalidate-buffa/commit/1891db1e1b523709c647455da876e75becd4597e))


### Build System

* Update buffa to 0.9.1 and connectrpc to 0.9.0 ([#29](https://github.com/mathematic-inc/protovalidate-buffa/issues/29)) ([f973190](https://github.com/mathematic-inc/protovalidate-buffa/commit/f97319002367b9fe42c77422434b796f664c2123))
* Update dependencies to latest ([c1d707d](https://github.com/mathematic-inc/protovalidate-buffa/commit/c1d707d30e92a32ddce4eb13738f6ab0442a7deb))
* Update dependencies to latest ([#23](https://github.com/mathematic-inc/protovalidate-buffa/issues/23)) ([acfe8a1](https://github.com/mathematic-inc/protovalidate-buffa/commit/acfe8a1b6285b1fdce95db178563e27919df2ac6))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * protovalidate-buffa-protos bumped from 0.7.0 to 0.7.1

## [0.7.3](https://github.com/mathematic-inc/protovalidate-buffa/compare/protoc-gen-protovalidate-buffa-v0.7.2...protoc-gen-protovalidate-buffa-v0.7.3) (2026-09-06)


### Bug Fixes

* **cel:** Preserve oneof presence semantics in `has()` expressions for owned messages and borrowed views, including nested and repeated messages.
* **cel:** Resolve repeated and recursive message schemas lazily so collection expressions can access their elements.
* **oneof:** Count selected default values correctly in message-level oneof rules and avoid direct field guards for oneof members.

## [0.7.2](https://github.com/mathematic-inc/protovalidate-buffa/compare/protoc-gen-protovalidate-buffa-v0.7.1...protoc-gen-protovalidate-buffa-v0.7.2) (2026-09-04)


### Bug Fixes

* **cel:** Preserve timestamp and duration values across bindings ([#45](https://github.com/mathematic-inc/protovalidate-buffa/issues/45)) ([94037da](https://github.com/mathematic-inc/protovalidate-buffa/commit/94037dafc3016f0c21eb13f68240d57011991614))
* **cel:** Read protobuf defaults for unset message fields ([#47](https://github.com/mathematic-inc/protovalidate-buffa/issues/47)) ([32742d4](https://github.com/mathematic-inc/protovalidate-buffa/commit/32742d49bda94fde507bc27fe8bed2d7fa578b1d))

## [0.7.1](https://github.com/mathematic-inc/protovalidate-buffa/compare/protoc-gen-protovalidate-buffa-v0.7.0...protoc-gen-protovalidate-buffa-v0.7.1) (2026-08-27)


### Bug Fixes

* **generator:** Use generic package examples ([#40](https://github.com/mathematic-inc/protovalidate-buffa/issues/40)) ([32f5ae1](https://github.com/mathematic-inc/protovalidate-buffa/commit/32f5ae16d7da9ccbce7b210e3e12389683599b25))

## [0.7.0](https://github.com/mathematic-inc/protovalidate-buffa/compare/protoc-gen-protovalidate-buffa-v0.6.0...protoc-gen-protovalidate-buffa-v0.7.0) (2026-08-27)

### ⚠ BREAKING CHANGES

* update buffa to 0.9.1 and connectrpc to 0.9.0 ([#29](https://github.com/mathematic-inc/protovalidate-buffa/issues/29))

### Features

* Validate buffa view types ([#34](https://github.com/mathematic-inc/protovalidate-buffa/issues/34)) ([bccef64](https://github.com/mathematic-inc/protovalidate-buffa/commit/bccef64f99e22586a4f9a89b6eb87b5ce914784f))

### Build System

* Update buffa to 0.9.1 and connectrpc to 0.9.0 ([#29](https://github.com/mathematic-inc/protovalidate-buffa/issues/29)) ([f973190](https://github.com/mathematic-inc/protovalidate-buffa/commit/f97319002367b9fe42c77422434b796f664c2123))

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

* Compile-time expansion of CEL rules; drop runtime interpreter
  ([#10](https://github.com/mathematic-inc/protovalidate-buffa/issues/10))
  ([ba01ffe](https://github.com/mathematic-inc/protovalidate-buffa/commit/ba01ffe75b6da086253c8366d266fbbd12c55e30))

### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * protovalidate-buffa-protos bumped from 0.2.0 to 0.3.0

## [0.2.1](https://github.com/mathematic-inc/protovalidate-buffa/compare/protoc-gen-protovalidate-buffa-v0.2.0...protoc-gen-protovalidate-buffa-v0.2.1) (2026-05-16)

### Features

* Complete protovalidate coverage ([bbe9772](https://github.com/mathematic-inc/protovalidate-buffa/commit/bbe977247acd9afdc6c23c6e8c3be4bcdb12e114))

## [0.2.0](https://github.com/mathematic-inc/protovalidate-buffa/compare/protoc-gen-protovalidate-buffa-v0.1.2...protoc-gen-protovalidate-buffa-v0.2.0) (2026-05-09)

### ⚠ BREAKING CHANGES

* requires Rust 1.95+ and edition 2024; depends on buffa 0.5 (was 0.4) and
  connectrpc 0.4 (was 0.3).

### Bug Fixes

* Bump buffa to 0.5.2, update edition to 2024, all dependencies to latest
  ([#4](https://github.com/mathematic-inc/protovalidate-buffa/issues/4))
  ([743de86](https://github.com/mathematic-inc/protovalidate-buffa/commit/743de8677046d84deb2383bf453f1e62fbc195db))

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
