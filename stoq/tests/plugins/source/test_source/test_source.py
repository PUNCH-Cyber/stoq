#   Copyright 2014-2015 PUNCH Cyber Analytics Group
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

"""

Overview
========

Test stoQ source

"""

import os

try:
    # Use the built-in version of scandir/walk (3.5+), otherwise
    from os import scandir, walk
except ImportError:
    # use the scandir module version
    from scandir import scandir, walk

from stoq.plugins import StoqSourcePlugin


class TestSource(StoqSourcePlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq
        super().activate()

    def ingest(self):
        """
        Test stoQ source
        """

        # Scan an entire directory
        if os.path.isdir(self.stoq.worker.path):
            if self.recursive:
                for root_path, subdirs, files in walk(self.stoq.worker.path):
                    for entry in files:
                        path = os.path.join(root_path, entry)
                        self.stoq.worker.multiprocess_put(path=path, archive='file')
            else:
                for entry in scandir(self.stoq.worker.path):
                    if not entry.name.startswith('.') and entry.is_file():
                        path = os.path.join(self.stoq.worker.path, entry.name)
                        self.stoq.worker.multiprocess_put(path=path, archive='file')

        # Only scanning a single file
        elif os.path.isfile(self.stoq.worker.path):
            self.stoq.worker.multiprocess_put(path=self.stoq.worker.path,
                                              archive='file')

        return True
