Multiclass Plugins
==================

Plugins that are of more than one plugin class are called `Multiclass Plugins`.
`Multiclass plugins` help to simplify and centralize plugin code. Development
is nearly identical to creating a regular plugin.In order to create a
`Multiclass plugin`, the plugin must be a subclass of one or more plugin class.

In this example, we will create a `Multiclass plugin` that is a worker as well
as a dispatcher plugin. We simply need to subclass our plugin class with
``WorkerPlugin`` and ``DispatcherPlugin`` and ensure the ``scan`` (required
for worker plugins) and ``get_dispatches`` (required for dispatcher plugins)
methods exist.::

    from typing import Optional
    from stoq.plugins import DispatcherPlugin, WorkerPlugin

    class MultiClassPlugin(WorkerPlugin, DispatcherPlugin):
        def scan(
            self, payload: Payload, request_meta: RequestMeta
        ) -> Optional[WorkerResponse]:
            # do worker plugin stuff here
            return

        def get_dispatches(
            self, payload: Payload, request_meta: RequestMeta
        ) -> Optional[DispatcherResponse]:
            # do dispatcher plugin stuff here
            return

