# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Allow `--plugin-dir` from command line to force one or more plugin directories

## [2.0.2] - 2019-01-14

### Changed

- Fix erroneous error from being displayed when installing or listing plugins
- Fix plugin install if requirements.txt does not exist
- Documentation update for installation (@chemberger)

## [2.0.1] - 2019-01-10

### Added

- Allow `--max-recursion` from command line and `max_recursion` when instantiating `Stoq()`.
- Allow `max_dispatch_passes` when instantiating `Stoq()`.
- Allow `--request-source` and `--request-extra` from command line.

### Changed

- Fix requirements URL when installing plugins from stoQ plugin repository
- Minor bug fixes

## [2.0.0] - 2018-12-21

### Added

- Initial v2 release.
