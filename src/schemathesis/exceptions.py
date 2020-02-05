from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
from builtins import str
from future import standard_library
standard_library.install_aliases()
from hashlib import sha1
from typing import Dict, Type, Union

import attr
import requests
from jsonschema import ValidationError

from .utils import WSGIResponse

CACHE = {}


def get_exception(name):
    """Create a new exception class with provided name or fetch one from cache."""
    if name in CACHE:
        exception_class = CACHE[name]
    else:
        exception_class = type(name, (AssertionError,), {})
        CACHE[name] = exception_class
    return exception_class


def _get_hashed_exception(prefix, message):
    """Give different exceptions for different error messages."""
    messages_digest = sha1(message.encode("utf-8")).hexdigest()
    name = "{prefix}{messages_digest}".format(prefix=prefix, messages_digest)
    return get_exception(name)


def get_grouped_exception(*exceptions):
    messages = [exception.args[0] for exception in exceptions]
    message = "".join(messages)
    return _get_hashed_exception("GroupedException", message)


def get_status_code_error(status_code):
    """Return new exception for an unexpected status code."""
    name = "StatusCodeError{status_code}".format(status_code=status_code)
    return get_exception(name)


def get_response_type_error(expected, received):
    """Return new exception for an unexpected response type."""
    name = "SchemaValidationError{expected}_{received}".format(expected=expected, received=received)
    return get_exception(name)


def get_schema_validation_error(exception):
    """Return new exception for schema validation error."""
    return _get_hashed_exception("SchemaValidationError", str(exception))


class InvalidSchema(Exception):
    """Schema associated with an endpoint contains an error."""


@attr.s
class HTTPError(Exception):
    response = attr.ib(type=Union[requests.Response, WSGIResponse])
    url = attr.ib(type=str)
