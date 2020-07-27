# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.1] - 2020-07-27

### Added

- Add `getjson()` function to allow plugins to use valid json strings are configuration 
    options (@ytreister, #144)

### Changed

- Fix stoq command line to properly parsed `--plugin-opts` and `--request-source` 
    arguments that contain `=` or `:` characters
- Ensure `always_dispatch` in `stoq.cfg` leverages `getlist()` when `Stoq()` is
    is instantiated. (#149) 
- Multiple fixes and updates to Dockerfile

## [3.0.0] - 2020-03-18

### Added

- Support for asyncio within the framework and plugins
- Better type checking support
- `self.log` may be leveraged from within all plugin classes
- Add new `Error()` class for standardizing errors from stoQ and plugins
    `Error()` will track plugin name, error message, and payload_id (optional)
- Add configuration properties from `[Core]` and `[Documentation]` to each plugin object when loaded 
- `PayloadMeta` now has a `should_scan` boolean.
    Allows payloads to be logged and archived, but not scanned by worker plugin.
- `Payload` is now updated as results are completed.
    Results from completed scans will be available to other plugins instantly
- `Request()` class is passed to all dispatchers, workers, and archiver plugins.
    The `Request` object contains all payloads, request metadata, results, and errors from 
    all other completed plugins. This will allow for all neccessary plugins to have a full 
    understanding of the current state of the complete `Request`.
- `WorkerPlugin`s now have a configuration option of `required_workers`.
    This allows for chained worker dependencies. If `required_workers` is defined, the 
    parent plugin will not be run until all required plugins are completed successfully. The
    parent plugin may then use results from other completed plugins for their respective 
    scanning tasks.
- Duplicate extracted payloads are no longer simply skipped, they are appended to 
    `Payload.results[].extracted_by` and `Payload.results[].extracted_from`  
- Add `StoqConfigParser` to `stoq.helpers` to extend options for `Stoq` and plugin configurations.
- Parallelization is performed across all of the plugins that can run in a given round, 
    instead of parallelizing across all of the plugins to perform on a given payload (#147)
- Ensure `plugin_name` is set to the name of the plugin class in case `Name` is not defined in 
    the plugin's configuration.

### Changed

- `PayloadResults` is now an object of `Payload.results`, rather than an independent object
- Most objects have been removed from `Payload` and are now availabe in `Payload.results`, 
    namely `extracted_by`, `extracted_from`, `payload_id`, `size`, `payload_meta`
- `Payload.plugins_run` moved to `PayloadResults.plugins_run` and is now a `Dict[str, List[str]]` 
    rather than `Dict[str, List[List[str]]]`
- `PayloadResults.workers` is now a `Dict[str, Dict]` rather than `List[Dict[str, Dict]]`
- `PayloadMeta` is now an object of `PayloadResults.payload_meta` 
- `PayloadResults.extracted_by` is now a `List[str]` rather than `str`
- `PayloadResults.extracted_from` is now a `List[str]` rather than `str`
- Dispatchers run on each payload every round, instead of once per payload. This allows 
    the dispatcher to take advantage of the request state model. (#147)
- Worker plugins can specify additional plugins to run on the payload they scan, effectively giving them dispatch capability.
    With YARA, for example, this allows us to directly scan with YARA and dispatch 
    to other plugins by running YARA once. Otherwise, we would run YARA as a dispatcher, 
    and then immediately run YARA again as a worker plugin. (#147)
- Archivers run at the very end along with connectors and decorators because we no 
    longer scan a payload to completion at once. (#147)
- The default value for max_recursion has increased because the average number of 
    worker rounds taken to complete a scan is expected to increase. (#147)


### Deprecated

- DeepDispatcher plugin class has been removed
- `Payload.plugins_run` has been removed in favor of `PayloadResults.plugins_run
- `Payload.worker_results` has been removed in favor of `PayloadResults.workers`
- `RequestMeta` is no longer passed to plugins, in favor of the `Request` object
- `plugins_opts` has been removed from plugin `__init__` function. All plugin configuration options
    are only available in `self.config`

## [2.0.7] - 2019-11-18

### Changed

- Fix plugin requirements path when installing from Github

## [2.0.6] - 2019-11-08

### Changed

- Fix issue where deep dispatchers defined from the CLI were not passed to `Stoq()`
- Update URL for plugins to include v2 branch when using `--github`

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
