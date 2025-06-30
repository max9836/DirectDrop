class InvalidArgsCombo(Exception):
    def __init__(
        self,
        message=(
            "The provided combination of arguments is invalid. "
            "Please see README.md for more information."
        )
    ):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"InvalidArgsCombo: {self.message}"

class NoConnectionError(Exception):
    def __init__(self, message="No connection could be established."):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"NoConnectionError: {self.message}"

class ConnectionTerminatedByClientException(Exception):
    def __init__(self, message="The connection is terminated by the client. This error is common when the client terminated the transfer process, or when an unexpected error occured in the client script. Please check the client script and fix the error from there."):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"ConnectionTerminatedByClientException: {self.message}"

class InvalidKeyOnClientError(Exception):
    def __init__(self, message="The encryption key does not match between the server and client. Please make sure the client is started with the '-e' or '--encrypt' option and the correct password."):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"InvalidKeyOnClientError: {self.message}"

class CorruptedPacket(Exception):
    def __init__(self, message="A corrupted packet was received. Try increasing the 'throttling_delay' variable in config.py on the server side."):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"CorruptedPacket: {self.message}"

class StrictModeImbalanceException(Exception):
    def __init__(self, message="You must either use strict mode on both system or not use strict mode at all."):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"StrictModeImbalanceException: {self.message}"

class LowMemModeImbalanceException(Exception):
    def __init__(self, message="Low-memory mode must be enabled or disabled consistently on both server and client."):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"LowMemModeImbalanceException: {self.message}"

class PacketChunkSizeNotMatch(Exception):
    def __init__(self, message = "The packet chunk size does not match between server and client. Please ensure that you have same packet chunk size for your mode in both your server and client"):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"PacketChunkSizeNotMatch {self.message}"

class EncryptionError(Exception):
    def __init__(self, message = "Unexpected Error in encryption system"):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"Encryption Error: {self.message}"
