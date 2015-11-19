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

Examples
========

"""

import time
import threading
from hydra import UpdatingBloomFilter, WritingBloomFilter


class StoqBloomFilter(object):
    def query_filter(self, item, add_missing=False):
        """
        Identify whether an item exists within filter or not

        :param bytes item: Item to query the bloom filter with
        :param bool add_missing: If set to True, the item will be added tothe bloom filter if it doesn't exist

        :returns: True if item exists, False if not.
        :rtype: bool

        """
        item_present = self.current_filter.contains(item)

        if add_missing and not item_present:
            self.current_filter.add(item)

        return item_present

    def create_filter(self, filepath, size, falsepos_rate):
        """
        Create new bloom filter

        :param bytes filepath: Path to persistent bloom filter on disk
        :param int size: Maximum number of elements in bloom filter
        :param float falsepos_rate: Maximum false positive probability

        """
        self.current_filter = WritingBloomFilter(int(size), float(falsepos_rate),
                                                 filename=filepath)

    def import_filter(self, filepath):
        """
        Load a previously created persistent bloom filter

        :param bytes filepath: Path to persistent bloom filter on disk

        """
        self.current_filter = UpdatingBloomFilter(filepath)

    def backup_scheduler(self, interval):
        """
        Set a syncing schedule for the persistent bloom filter

        :param int interval: Interval between syncing bloom filter to disk

        """

        backup = threading.Thread(target=self._backup, args=(int(interval),))
        backup.daemon = True
        backup.start()

    def _backup(self, interval):
        """
        Sync persistent bloom filter to disk

        :param int interval: Interval between syncing bloom filter to disk

        """

        if interval > 0:
            # Continuously sync bloom filter at interval
            while True:
                time.sleep(interval)
                self.current_filter.fdatasync()
        else:
            # If no positive interval set, sync once
            self.current_filter.fdatasync()

