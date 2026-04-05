# Changelog

## [0.1.1](https://github.com/rcd27/flowsense/compare/v0.1.0...v0.1.1) (2026-04-05)


### Features

* **core:** proof of concept ([3bb9116](https://github.com/rcd27/flowsense/commit/3bb9116a8ca1a5e1beb4f8f4be032c408535517a))
* **docker:** add entrypoint script with bridge + SOCKS5 topology ([da7db8e](https://github.com/rcd27/flowsense/commit/da7db8ed2d7d43456609003b7852ea698b106a70))
* **docker:** appropriate docker image for e2e testing/prod ([344000a](https://github.com/rcd27/flowsense/commit/344000a9964dfad2215d1a014085d341cea44ac0))
* **docker:** e2e testing container with bridge + HTTP proxy + DPI detection fixes ([b2c9d8a](https://github.com/rcd27/flowsense/commit/b2c9d8a59c0182af8d99a9323a7140872dcf5b1a))
* **docker:** multi-stage Dockerfile with flowsense + microsocks ([fdeb17a](https://github.com/rcd27/flowsense/commit/fdeb17a73eb11c648853fc36b8b6b3f84b66d863))
* **docs:** add specification ([ff450f0](https://github.com/rcd27/flowsense/commit/ff450f01722602dcd406c044cc00aeb1b087ba01))
* **protocol:** Component Protocol for stdout ([57823ed](https://github.com/rcd27/flowsense/commit/57823ed2284a0478bc130d918c9cdb147ce63855))
* **testing:** L2 specific use-case tested. flowsense doesn't work properly on "localhost" without bridge ([c0698d9](https://github.com/rcd27/flowsense/commit/c0698d9c27559f04203365388fe54050d92d9452))


### Bug Fixes

* **ddd:** more ADT ftw ([93701b6](https://github.com/rcd27/flowsense/commit/93701b6195f25cdf05e17f05d44be2c3f371e2b5))
* **flow:** reduce false positives detection for all existing detectors ([a50316d](https://github.com/rcd27/flowsense/commit/a50316d5966e9350a292e00ebbcc182ee21ab4b9))
* **lint:** cargo fmt for all targets ([5ce1f79](https://github.com/rcd27/flowsense/commit/5ce1f796d155ecb324b644d52119edaf708c1964))
* **linter:** possible unwrap ([78f47d6](https://github.com/rcd27/flowsense/commit/78f47d6cb699bdb84bd3378b6d8c416877304290))
* **protocol:** missing files ([8e90353](https://github.com/rcd27/flowsense/commit/8e9035327c67b26a1486cc1483bb423062fc1d6b))
* resolve clippy warnings (abs_diff, then_some, is_none_or, matches!, is_empty) ([92766ab](https://github.com/rcd27/flowsense/commit/92766ab0fe27c0d8f5e11a6292c6039710467eb1))
* **rst-injection:** 0% false positives ([41624a3](https://github.com/rcd27/flowsense/commit/41624a3d904429dd447b411127374b736edb2f08))
* **types:** типизированные ошибки + паника + правки по TODO ([492f67b](https://github.com/rcd27/flowsense/commit/492f67be8c8e9b84ef5fc36479331549c224feeb))
