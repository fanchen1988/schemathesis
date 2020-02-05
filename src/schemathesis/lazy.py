from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
from future import standard_library
standard_library.install_aliases()
from builtins import object
from inspect import signature
from typing import Any, Callable, Dict, Optional, Union

import attr
import pytest
from _pytest.fixtures import FixtureRequest
from pytest_subtests import SubTests

from .exceptions import InvalidSchema
from .models import Endpoint
from .schemas import BaseSchema
from .types import Filter
from .utils import NOT_SET


@attr.s(slots=True)  # pragma: no mutate
class LazySchema(object):
    fixture_name = attr.ib(type=str)  # pragma: no mutate
    method = attr.ib(default=NOT_SET, type=Optional[Filter])  # pragma: no mutate
    endpoint = attr.ib(default=NOT_SET, type=Optional[Filter])  # pragma: no mutate
    tag = attr.ib(default=NOT_SET, type=Optional[Filter])  # pragma: no mutate

    def parametrize(
        self, method = NOT_SET, endpoint = NOT_SET, tag = NOT_SET
    ):
        if method is NOT_SET:
            method = self.method
        if endpoint is NOT_SET:
            endpoint = self.endpoint
        if tag is NOT_SET:
            tag = self.tag

        def wrapper(func):
            def test(request, subtests):
                """The actual test, which is executed by pytest."""
                schema = get_schema(request, self.fixture_name, method, endpoint, tag)
                fixtures = get_fixtures(func, request)
                # Changing the node id is required for better reporting - the method and endpoint will appear there
                node_id = subtests.item._nodeid
                settings = getattr(test, "_hypothesis_internal_use_settings", None)
                for _endpoint, sub_test in schema.get_all_tests(func, settings):
                    actual_test = get_test(sub_test)
                    subtests.item._nodeid = _get_node_name(node_id, _endpoint)
                    run_subtest(_endpoint, fixtures, actual_test, subtests)
                subtests.item._nodeid = node_id

            # Needed to prevent a failure when settings are applied to the test function
            test.is_hypothesis_test = True  # type: ignore

            return test

        return wrapper


def get_test(test):
    """For invalid schema exceptions construct a failing test function, return the original test otherwise."""
    if isinstance(test, InvalidSchema):
        message = test.args[0]

        def actual_test(*args, **kwargs):
            pytest.fail(message)

        return actual_test
    return test


def _get_node_name(node_id, endpoint):
    """Make a test node name. For example: test_api[GET:/v1/users]."""
    return "{node_id}[{method}:{path}]".format(node_id=node_id, method=endpoint.method, path=endpoint.path)


def run_subtest(endpoint, fixtures, sub_test, subtests):
    """Run the given subtest with pytest fixtures."""
    with subtests.test(method=endpoint.method, path=endpoint.path):
        sub_test(**fixtures)


def get_schema(
    request,
    name,
    method = None,
    endpoint = None,
    tag = None,
):
    """Loads a schema from the fixture."""
    schema = request.getfixturevalue(name)
    if not isinstance(schema, BaseSchema):
        raise ValueError("The given schema must be an instance of BaseSchema, got: {schema_type}".format(schema_type=type(schema)))
    if method is NOT_SET:
        method = schema.method
    if endpoint is NOT_SET:
        endpoint = schema.endpoint
    if tag is NOT_SET:
        tag = schema.tag
    return schema.__class__(schema.raw_schema, method=method, endpoint=endpoint, tag=tag)


def get_fixtures(func, request):
    """Load fixtures, needed for the test function."""
    sig = signature(func)
    return {name: request.getfixturevalue(name) for name in sig.parameters if name != "case"}
