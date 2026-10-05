"""The base error for anything that makes a single request fail."""


class RequestError(Exception):
    """Raised when one request cannot be turned into a layer; the other requests still run."""
