from stoq.plugins.base import StoqPluginBase


class StoqDecoderPlugin(StoqPluginBase):

    def decode(self):
        pass

    def to_bytearray(self, payload):
        """
        Convert payload to a bytearray

        :param bytes payload: Payload to be converted into byte array

        :returns: Payload as a bytearray
        :rtype: bytearray

        """
        self.log.debug("Converting payload ({} bytes) to a bytearray".format(len(payload)))
        if isinstance(payload, bytearray):
            pass
        elif isinstance(payload, bytes):
            payload = bytearray(payload)

        else:
            payload = bytearray(payload.encode())

        return payload
