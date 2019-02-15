# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Allow `--plugin-dir` from command line to force one or more plugin directories
- Provide better logging when a plugin is installed from github as a non-root user outside of a venv
- Gracefully handle exceptions in `ConnectorPlugins`

### Changed

- Improve handling of plugin configuration options. Plugin options can now also be in stoq.cfg. (Thanks for feedback @chemberger!)
- Set default precendence for plugin configuration options to be 1) `plugin_opts` when instantiating `Stoq`, 2) `stoq.cfg`, 3) Plugin config file (Thanks for feedback @chemberger!)
- Make formatted exceptions more legible in results

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
