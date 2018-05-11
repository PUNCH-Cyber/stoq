import multiprocessing

from stoq.plugins.base import StoqPluginBase

class StoqSourcePlugin(StoqPluginBase, multiprocessing.Process):

    def ingest(self):
        pass