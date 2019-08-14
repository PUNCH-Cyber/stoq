# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased (pre-v3.0)

### Added

- Support for asyncio within the framework and plugins
- Better type checking support
- `self.log` may be leveraged from within all plugin classes
- Add new `Error()` class for standardizing errors from stoQ and plugins
    `Error()` will track plugin name, error message, and payload_id (optional)
- Add configuration properties from `[Core]` and `[Documentation]` to each plugin object when loaded 
- `PayloadMeta` now has a `should_scan` boolean which will allow payloads to be logged and archived, but not scanned by worker plugin
- `Request()` class is passed to all dispatchers, workers, and archiver plugins.
    The `Request` object contains all payloads, request metadata, results, and errors from all other plugins. This will allow for all neccessary plugins
    to have a full understanding of the current state of the `Request`.

### Changed

- `Payload.plugins_run` moved to `PayloadResults.plugins_runs` and is now a `Dict[str, List[str]]` rather than `Dict[str, List[List[str]]]`
- `Payload.worker_results` is now a `Dict[str, List[str]]` rather than `List[Dict[str, Dict]]`
- `PayloadResults.workers` is now a `Dict[str, Dict]` rather than `List[Dict[str, Dict]]`

### Deprecated

- DeepDispatcher plugin class
- `Payload.plugins_run` has been removed in favor of `PayloadResults.plugins_run`)
- `RequestMeta` is no longer passed to plugins, in favor of the `Request` object.

## [2.0.5] - 2019-06-07

### Added

- Provide console output if stoQ configuration file does not exist (Thanks for feedback @jakubgs!)
- Add command line option `--config-file` to define stoQ configuration file
- Add command line option `--log-level` to allow for setting of the log level
- Documentation for simplied method of defining plugin options within `__init__`

### Changed

- Raise StoqPluginException if installing a plugin that is already installed
- Display `plugin_path` when plugin is successfully installed
- Raise StoqPluginNotFound when attempting to load non-existent or invalid plugin

## [2.0.4] - 2019-03-29

### Added

- `Stoq.reconstruct_all_subresponses()` method to allow for reconstructing `StoqResponse` objects iteratively (@maydewd)

### Changed

- Force payload content to be of type `bytes`

## [2.0.3] - 2019-02-15

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
