from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
# pylint: disable=too-many-instance-attributes
from builtins import dict
from builtins import object
from future import standard_library
standard_library.install_aliases()
#from collections import Counter
#from contextlib import contextmanager
from enum import IntEnum
#from logging import LogRecord
from typing import TYPE_CHECKING, Any, Callable, Dict, Generator, Iterator, List, Optional, Tuple, Union
from urllib.parse import urljoin

import attr
#import requests
#import werkzeug
#from hypothesis.strategies import SearchStrategy

from .checks import ALL_CHECKS
from .exceptions import InvalidSchema
from .types import Body, Cookies, FormData, Headers, PathParameters, Query
#from .utils import WSGIResponse

if TYPE_CHECKING:
    from .schemas import BaseSchema


@attr.s(slots=True)  # pragma: no mutate
class Case(object):
    """A single test case parameters."""

    endpoint = attr.ib(type="Endpoint")  # pragma: no mutate
    path_parameters = attr.ib(default=None, type=Optional[PathParameters])  # pragma: no mutate
    headers = attr.ib(default=None, type=Optional[Headers])  # pragma: no mutate
    cookies = attr.ib(default=None, type=Optional[Cookies])  # pragma: no mutate
    query = attr.ib(default=None, type=Optional[Query])  # pragma: no mutate
    body = attr.ib(default=None, type=Optional[Body])  # pragma: no mutate
    form_data = attr.ib(default=None, type=Optional[FormData])  # pragma: no mutate

    @property
    def path(self):
        return self.endpoint.path

    @property
    def method(self):
        return self.endpoint.method

    @property
    def base_url(self):
        return self.endpoint.base_url

    @property
    def app(self):
        return self.endpoint.app

    @property
    def formatted_path(self):
        # pylint: disable=not-a-mapping
        try:
            return self.path.format(**(self.path_parameters or {}))
        except KeyError:
            raise InvalidSchema("Missing required property `required: true`")

    #def get_code_to_reproduce(self):
    #    """Construct a Python code to reproduce this case with `requests`."""
    #    base_url = self.base_url or "http://localhost"
    #    kwargs = self.as_requests_kwargs(base_url)
    #    method = kwargs["method"].lower()

    #    def are_defaults(key, value):
    #        default_value = {"json": None}.get(key, None)
    #        return value == default_value

    #    printed_kwargs = ", ".join(
    #        "{key}={value}".format(key=key, value=value)
    #        for key, value in kwargs.items()
    #        if key not in ("method", "url") and not are_defaults(key, value)
    #    )
    #    args_repr = "'{url}'".format(url=kwargs['url'])
    #    if printed_kwargs:
    #        args_repr += ", {printed_kwargs}".format(printed_kwargs=printed_kwargs)
    #    return "requests.{method}({args_repr})".format(method=method, args_repr=args_repr)

    def _get_base_url(self, base_url = None):
        if base_url is None:
            if self.base_url is not None:
                base_url = self.base_url
            else:
                raise ValueError(
                    "Base URL is required as `base_url` argument in `call` or should be specified "
                    "in the schema constructor as a part of Schema URL."
                )
        return base_url

    def as_requests_kwargs(self, base_url = None):
        """Convert the case into a dictionary acceptable by requests."""
        base_url = self._get_base_url(base_url)
        formatted_path = self.formatted_path.lstrip("/")  # pragma: no mutate
        url = urljoin(base_url + "/", formatted_path)
        # Form data and body are mutually exclusive
        if self.form_data:
            extra = {"files": self.form_data}
        elif isinstance(self.body, bytes):
            extra = {"data": self.body}
        else:
            extra = {"json": self.body}
        return dict({
            "method": self.method,
            "url": url,
            "cookies": self.cookies,
            "headers": self.headers,
            "params": self.query,
        }, **extra)

    #def call(
    #    self, base_url = None, session = None, **kwargs
    #):
    #    """Make a network call with `requests`."""
    #    if session is None:
    #        session = requests.Session()
    #        close_session = True
    #    else:
    #        close_session = False

    #    base_url = self._get_base_url(base_url)
    #    data = self.as_requests_kwargs(base_url)
    #    response = session.request(**dict(data, **kwargs))  # type: ignore
    #    if close_session:
    #        session.close()
    #    return response

    #def as_werkzeug_kwargs(self):
    #    """Convert the case into a dictionary acceptable by werkzeug.Client."""
    #    headers = self.headers
    #    if self.form_data:
    #        extra = {"data": self.form_data}
    #        headers = headers or {}
    #        headers.setdefault("Content-Type", "multipart/form-data")
    #    elif isinstance(self.body, bytes):
    #        extra = {"data": self.body}
    #    else:
    #        extra = {"json": self.body}
    #    return dict({
    #        "method": self.method,
    #        "path": self.formatted_path,
    #        "headers": headers,
    #        "query_string": self.query,
    #    }, **extra)

    #def call_wsgi(self, app = None, headers = None, **kwargs):
    #    application = app or self.app
    #    if application is None:
    #        raise RuntimeError(
    #            "WSGI application instance is required. "
    #            "Please, set `app` argument in the schema constructor or pass it to `call_wsgi`"
    #        )
    #    data = self.as_werkzeug_kwargs()
    #    if headers:
    #        data["headers"] = data["headers"] or {}
    #        data["headers"].update(headers)
    #    client = werkzeug.Client(application, WSGIResponse)
    #    with cookie_handler(client, self.cookies):
    #        return client.open(**dict(data, **kwargs))

    def validate_response(
        self,
        response,
        checks = ALL_CHECKS,
    ):
        errors = []
        for check in checks:
            try:
                check(response, self)
            except AssertionError as exc:
                errors.append(exc.args[0])
        if errors:
            raise AssertionError(*errors)


#@contextmanager
#def cookie_handler(client, cookies):
#    """Set cookies required for a call."""
#    if not cookies:
#        yield
#    else:
#        for key, value in cookies.items():
#            client.set_cookie("localhost", key, value)
#        yield
#        for key in cookies:
#            client.delete_cookie("localhost", key)
#
#
def empty_object():
    return {"properties": {}, "additionalProperties": False, "type": "object", "required": []}


@attr.s(slots=True)  # pragma: no mutate
class Endpoint(object):
    """A container that could be used for test cases generation."""

    path = attr.ib(type=str)  # pragma: no mutate
    method = attr.ib(type=str)  # pragma: no mutate
    definition = attr.ib(type=Dict[str, Any])  # pragma: no mutate
    schema = attr.ib(type="BaseSchema")  # pragma: no mutate
    app = attr.ib(default=None, type=Any)  # pragma: no mutate
    base_url = attr.ib(default=None, type=Optional[str])  # pragma: no mutate
    path_parameters = attr.ib(default=None, type=Optional[PathParameters])  # pragma: no mutate
    headers = attr.ib(default=None, type=Optional[Headers])  # pragma: no mutate
    cookies = attr.ib(default=None, type=Optional[Cookies])  # pragma: no mutate
    query = attr.ib(default=None, type=Optional[Query])  # pragma: no mutate
    body = attr.ib(default=None, type=Optional[Body])  # pragma: no mutate
    form_data = attr.ib(default=None, type=Optional[FormData])  # pragma: no mutate

    def as_strategy(self):
        from ._hypothesis import get_case_strategy  # pylint: disable=import-outside-toplevel

        return get_case_strategy(self)


#class Status(IntEnum):
#    """Status of an action or multiple actions."""
#
#    success = 1  # pragma: no mutate
#    failure = 2  # pragma: no mutate
#    error = 3  # pragma: no mutate
#
#
#@attr.s(slots=True, repr=False)  # pragma: no mutate
#class Check(object):
#    """Single check run result."""
#
#    name = attr.ib(type=str)  # pragma: no mutate
#    value = attr.ib(type=Status)  # pragma: no mutate
#    example = attr.ib(default=None, type=Optional[Case])  # pragma: no mutate
#    message = attr.ib(default=None, type=Optional[str])  # pragma: no mutate
#
#
#@attr.s(slots=True, repr=False)  # pragma: no mutate
#class TestResult(object):
#    """Result of a single test."""
#
#    endpoint = attr.ib(type=Endpoint)  # pragma: no mutate
#    checks = attr.ib(factory=list, type=List[Check])  # pragma: no mutate
#    errors = attr.ib(factory=list, type=List[Tuple[Exception, Optional[Case]]])  # pragma: no mutate
#    logs = attr.ib(factory=list, type=List[LogRecord])  # pragma: no mutate
#    is_errored = attr.ib(default=False, type=bool)  # pragma: no mutate
#    seed = attr.ib(default=None, type=Optional[int])  # pragma: no mutate
#
#    def mark_errored(self):
#        self.is_errored = True
#
#    @property
#    def has_errors(self):
#        return bool(self.errors)
#
#    @property
#    def has_failures(self):
#        return any(check.value == Status.failure for check in self.checks)
#
#    @property
#    def has_logs(self):
#        return bool(self.logs)
#
#    def add_success(self, name, example):
#        self.checks.append(Check(name, Status.success, example))
#
#    def add_failure(self, name, example, message):
#        self.checks.append(Check(name, Status.failure, example, message))
#
#    def add_error(self, exception, example = None):
#        self.errors.append((exception, example))
#
#
#@attr.s(slots=True, repr=False)  # pragma: no mutate
#class TestResultSet(object):
#    """Set of multiple test results."""
#
#    results = attr.ib(factory=list, type=List[TestResult])  # pragma: no mutate
#
#    def __iter__(self):
#        return iter(self.results)
#
#    @property
#    def is_empty(self):
#        """If the result set contains no results."""
#        return len(self.results) == 0
#
#    @property
#    def has_failures(self):
#        """If any result has any failures."""
#        return any(result.has_failures for result in self)
#
#    @property
#    def has_errors(self):
#        """If any result has any errors."""
#        return any(result.has_errors for result in self)
#
#    @property
#    def has_logs(self):
#        """If any result has any captured logs."""
#        return any(result.has_logs for result in self)
#
#    def _count(self, predicate):
#        return sum(1 for result in self if predicate(result))
#
#    @property
#    def passed_count(self):
#        return self._count(lambda result: not result.has_errors and not result.has_failures)
#
#    @property
#    def failed_count(self):
#        return self._count(lambda result: result.has_failures and not result.is_errored)
#
#    @property
#    def errored_count(self):
#        return self._count(lambda result: result.has_errors or result.is_errored)
#
#    @property
#    def total(self):
#        """Aggregated statistic about test results."""
#        output = {}
#        for item in self.results:
#            for check in item.checks:
#                output.setdefault(check.name, Counter())
#                output[check.name][check.value] += 1
#                output[check.name]["total"] += 1
#        # Avoid using Counter, since its behavior could harm in other places:
#        # `if not total["unknown"]:` - this will lead to the branch execution
#        # It is better to let it fail if there is a wrong key
#        return {key: dict(value) for key, value in output.items()}
#
#    def append(self, item):
#        """Add a new item to the results list."""
#        self.results.append(item)
