from stoq.plugins.base import StoqPluginBase


class StoqCarverPlugin(StoqPluginBase):

    def carve(self):
        pass

    def carve_payload(self, regex, payload, ignorecase=False):
        """
        Generator that returns a list of offsets for a specified value
        within a payload

        :param bytes regex: Regular expression to search for
        :param bytes payload: Payload to be searched against
        :param bool ignorecase: True or False, use re.IGNORECASE

        :returns: Offset of value(s) discovered
        :rtype: generator

        """

        self.log.debug("Carve: Attempting to carve payload")
        try:
            payload = payload.read()
        except:
            pass

        if ignorecase:
            # Ignorecase, Multiline, Dot matches all
            flags = re.I|re.M|re.S
        else:
            # Multiline, Dot matches all
            flags = re.M|re.S

        for buff in re.finditer(regex, payload, flags):
            self.log.debug("Carve: Payload carve at offset {} - {}".format(buff.start(), buff.end()))
            yield buff.start(), buff.end()