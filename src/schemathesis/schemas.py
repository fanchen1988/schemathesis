# pylint: disable=too-many-instance-attributes
"""Schema objects provide a convenient interface to raw schemas.

Their responsibilities:
  - Provide a unified way to work with different types of schemas
  - Give all endpoints / methods combinations that are available directly from the schema;

They give only static definitions of endpoints.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
from builtins import open
from builtins import next
from builtins import super
from future import standard_library
standard_library.install_aliases()
import itertools
from collections.abc import Mapping
from copy import deepcopy
from functools import lru_cache
from typing import Any, Callable, Dict, Generator, Iterator, List, Optional, Tuple, Union, overload
from urllib.parse import urljoin, urlsplit

import attr
import hypothesis
import jsonschema
import yaml
from requests.structures import CaseInsensitiveDict

from ._hypothesis import make_test_or_exception
from .constants import HookLocation
from .converter import to_json_schema
from .exceptions import InvalidSchema
from .filters import should_skip_by_tag, should_skip_endpoint, should_skip_method
from .models import Endpoint, empty_object
from .types import Filter, Hook
from .utils import NOT_SET, StringDatesYAMLLoader


@lru_cache()
def load_file(location):
    """Load a schema from the given file."""
    with open(location) as fd:
        return yaml.load(fd, StringDatesYAMLLoader)


@attr.s()  # pragma: no mutate
class BaseSchema(Mapping):
    raw_schema = attr.ib(type=Dict[str, Any])  # pragma: no mutate
    location = attr.ib(default=None, type=Optional[str])  # pragma: no mutate
    base_url = attr.ib(default=None, type=Optional[str])  # pragma: no mutate
    method = attr.ib(default=None, type=Optional[Filter])  # pragma: no mutate
    endpoint = attr.ib(default=None, type=Optional[Filter])  # pragma: no mutate
    tag = attr.ib(default=None, type=Optional[Filter])  # pragma: no mutate
    app = attr.ib(default=None, type=Any)  # pragma: no mutate
    hooks = attr.ib(factory=dict, type=Dict[HookLocation, Hook])  # pragma: no mutate

    def __iter__(self):
        return iter(self.endpoints)

    def __getitem__(self, item):
        return self.endpoints[item]

    def __len__(self):
        return len(self.endpoints)

    @property  # pragma: no mutate
    def spec_version(self):
        raise NotImplementedError

    @property  # pragma: no mutate
    def verbose_name(self):
        raise NotImplementedError

    @property
    def endpoints(self):
        if not hasattr(self, "_endpoints"):
            # pylint: disable=attribute-defined-outside-init
            endpoints = self.get_all_endpoints()
            self._endpoints = endpoints_to_dict(endpoints)
        return self._endpoints

    @property
    def resolver(self):
        if not hasattr(self, "_resolver"):
            # pylint: disable=attribute-defined-outside-init
            self._resolver = jsonschema.RefResolver(self.location or "", self.raw_schema, handlers={"": load_file})
        return self._resolver

    @property
    def endpoints_count(self):
        return len(list(self.get_all_endpoints()))

    def get_all_endpoints(self):
        raise NotImplementedError

    def get_all_tests(
        self, func, settings = None, seed = None
    ):
        """Generate all endpoints and Hypothesis tests for them."""
        for endpoint in self.get_all_endpoints():
            test = make_test_or_exception(endpoint, func, settings, seed)
            yield endpoint, test

    def parametrize(
        self, method = NOT_SET, endpoint = NOT_SET, tag = NOT_SET
    ):
        """Mark a test function as a parametrized one."""
        if method is NOT_SET:
            method = self.method
        if endpoint is NOT_SET:
            endpoint = self.endpoint
        if tag is NOT_SET:
            tag = self.tag

        def wrapper(func):
            func._schemathesis_test = self.__class__(  # type: ignore
                self.raw_schema, base_url=self.base_url, method=method, endpoint=endpoint, tag=tag
            )
            return func

        return wrapper

    def _get_response_schema(self, definition):
        """Extract response schema from `responses`."""
        raise NotImplementedError

    def register_hook(self, place, hook):
        key = HookLocation[place]
        self.hooks[key] = hook

    def get_hook(self, place):
        key = HookLocation[place]
        return self.hooks.get(key)


class SwaggerV20(BaseSchema):
    nullable_name = "x-nullable"

    def __repr__(self):
        info = self.raw_schema["info"]
        return "{cls_name} for {title} ({version})".format(cls_name=self.__class__.__name__, title=info['title'], version=info['version'])

    @property
    def spec_version(self):
        return self.raw_schema["swagger"]

    @property
    def verbose_name(self):
        return "Swagger {spec_version}".format(spec_version=self.spec_version)

    @property
    def base_path(self):
        """Base path for the schema."""
        path = self.raw_schema.get("basePath", "/")  # pragma: no mutate
        if not path.endswith("/"):
            path += "/"
        return path

    def get_full_path(self, path):
        """Compute full path for the given path."""
        return urljoin(self.base_path, path.lstrip("/"))  # pragma: no mutate

    def get_all_endpoints(self):
        try:
            paths = self.raw_schema["paths"]  # pylint: disable=unsubscriptable-object
            for path, methods in paths.items():
                full_path = self.get_full_path(path)
                if should_skip_endpoint(full_path, self.endpoint):
                    continue
                methods = self.resolve(methods)
                common_parameters = get_common_parameters(methods)
                for method, definition in methods.items():
                    if (
                        method == "parameters"
                        or should_skip_method(method, self.method)
                        or should_skip_by_tag(definition.get("tags"), self.tag)
                    ):
                        continue
                    parameters = itertools.chain(definition.get("parameters", ()), common_parameters)
                    yield self.make_endpoint(full_path, method, parameters, definition)
        except (KeyError, AttributeError, jsonschema.exceptions.RefResolutionError):
            raise InvalidSchema("Schema parsing failed. Please check your schema.")

    def make_endpoint(
        self, full_path, method, parameters, definition
    ):
        """Create JSON schemas for query, body, etc from Swagger parameters definitions."""
        base_url = self.base_url
        if base_url is not None:
            base_url = base_url.rstrip("/")  # pragma: no mutate
        endpoint = Endpoint(
            path=full_path, method=method.upper(), definition=definition, base_url=base_url, app=self.app, schema=self
        )
        for parameter in parameters:
            self.process_parameter(endpoint, parameter)
        return endpoint

    def process_parameter(self, endpoint, parameter):
        """Convert each Parameter object to a JSON schema."""
        parameter = deepcopy(parameter)
        parameter = self.resolve(parameter)
        self.process_by_type(endpoint, parameter)

    def process_by_type(self, endpoint, parameter):
        if parameter["in"] == "path":
            self.process_path(endpoint, parameter)
        elif parameter["in"] == "query":
            self.process_query(endpoint, parameter)
        elif parameter["in"] == "header":
            self.process_header(endpoint, parameter)
        elif parameter["in"] == "body":
            # Could be only one parameter with "in=body"
            self.process_body(endpoint, parameter)
        elif parameter["in"] == "formData":
            self.process_form_data(endpoint, parameter)

    def process_path(self, endpoint, parameter):
        endpoint.path_parameters = self.add_parameter(endpoint.path_parameters, parameter)

    def process_header(self, endpoint, parameter):
        endpoint.headers = self.add_parameter(endpoint.headers, parameter)

    def process_query(self, endpoint, parameter):
        endpoint.query = self.add_parameter(endpoint.query, parameter)

    def process_body(self, endpoint, parameter):
        # "schema" is a required field
        endpoint.body = parameter["schema"]

    def process_form_data(self, endpoint, parameter):
        endpoint.form_data = self.add_parameter(endpoint.form_data, parameter)

    def add_parameter(self, container, parameter):
        """Add parameter object to the container."""
        name = parameter["name"]
        container = container or empty_object()
        container["properties"][name] = self.parameter_to_json_schema(parameter)
        if parameter.get("required", False):
            container["required"].append(name)
        return container

    def parameter_to_json_schema(self, data):
        """Convert Parameter object to a JSON schema."""
        return {
            key: value
            for key, value in data.items()
            # Do not include keys not supported by JSON schema
            if not (key == "required" and not isinstance(value, list))
        }

    @overload  # pragma: no mutate
    def resolve(self, item):  # pylint: disable=function-redefined
        pass

    @overload  # pragma: no mutate
    def resolve(self, item):  # pylint: disable=function-redefined
        pass

    # pylint: disable=function-redefined
    def resolve(self, item):
        """Recursively resolve all references in the given object."""
        if isinstance(item, dict):
            item = self.prepare(item)
            if "$ref" in item:
                with self.resolver.resolving(item["$ref"]) as resolved:
                    return self.resolve(resolved)
            for key, sub_item in item.items():
                item[key] = self.resolve(sub_item)
        elif isinstance(item, list):
            for idx, sub_item in enumerate(item):
                item[idx] = self.resolve(sub_item)
        return item

    def prepare(self, item):
        """Parse schema extension, e.g. "x-nullable" field."""
        return to_json_schema(item, self.nullable_name)

    def _get_response_schema(self, definition):
        return definition.get("schema")


class OpenApi30(SwaggerV20):  # pylint: disable=too-many-ancestors
    nullable_name = "nullable"

    @property
    def spec_version(self):
        return self.raw_schema["openapi"]

    @property
    def verbose_name(self):
        return "Open API {spec_version}".format(spec_version=self.spec_version)

    @property
    def base_path(self):
        """Base path for the schema."""
        servers = self.raw_schema.get("servers", [])
        if servers:
            # assume we're the first server in list
            server = servers[0]
            url = server["url"].format(**{k: v["default"] for k, v in server.get("variables", {}).items()})
            path = urlsplit(url).path
        else:
            path = "/"
        if not path.endswith("/"):
            path += "/"
        return path

    def make_endpoint(
        self, full_path, method, parameters, definition
    ):
        """Create JSON schemas for query, body, etc from Swagger parameters definitions."""
        endpoint = super().make_endpoint(full_path, method, parameters, definition)
        if "requestBody" in definition:
            self.process_body(endpoint, definition["requestBody"])
        return endpoint

    def process_by_type(self, endpoint, parameter):
        if parameter["in"] == "cookie":
            self.process_cookie(endpoint, parameter)
        else:
            super().process_by_type(endpoint, parameter)

    def add_parameter(self, container, parameter):
        container = super().add_parameter(container, parameter)
        if "example" in parameter:
            container["example"] = {parameter["name"]: parameter["example"]}
        return container

    def process_cookie(self, endpoint, parameter):
        endpoint.cookies = self.add_parameter(endpoint.cookies, parameter)

    def process_body(self, endpoint, parameter):
        # Take the first media type object
        options = iter(parameter["content"].values())
        parameter = next(options)
        super().process_body(endpoint, parameter)

    def parameter_to_json_schema(self, data):
        # "schema" field is required for all parameters in Open API 3.0
        return super().parameter_to_json_schema(data["schema"])

    def _get_response_schema(self, definition):
        options = iter(definition.get("content", {}).values())
        option = next(options, None)
        if option:
            return option["schema"]
        return None


def get_common_parameters(methods):
    """Common parameters are deep copied from the methods definitions.

    Copying is needed because of further modifications.
    """
    common_parameters = methods.get("parameters")
    if common_parameters is not None:
        return deepcopy(common_parameters)
    return []


def endpoints_to_dict(endpoints):
    output = {}
    for endpoint in endpoints:
        output.setdefault(endpoint.path, CaseInsensitiveDict())
        output[endpoint.path][endpoint.method] = endpoint
    return output
