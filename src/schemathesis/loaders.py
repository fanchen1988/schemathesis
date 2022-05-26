from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
# pylint: disable=too-many-arguments
from builtins import open
from builtins import object
from future import standard_library
standard_library.install_aliases()
#import os
#from typing import IO, Any, Callable, Dict, Optional, Union
#from urllib.parse import urljoin

import jsonschema
#import requests
import yaml
from jsonschema import ValidationError
#from werkzeug.test import Client

from . import spec_schemas
#from .constants import USER_AGENT
#from .exceptions import HTTPError
#from .lazy import LazySchema
from .schemas import BaseSchema, OpenApi30, SwaggerV20
#from .types import Filter
from .utils import  StringDatesYAMLLoader#, NOT_SET, WSGIResponse, deprecated, get_base_url


#def from_path(
#    path,
#    base_url = None,
#    method = None,
#    endpoint = None,
#    tag = None, **_3to2kwargs):
#    if 'validate_schema' in _3to2kwargs: validate_schema = _3to2kwargs['validate_schema']; del _3to2kwargs['validate_schema']
#    else: validate_schema =  True
#    if 'app' in _3to2kwargs: app = _3to2kwargs['app']; del _3to2kwargs['app']
#    else: app =  None
#    """Load a file from OS path and parse to schema instance."""
#    with open(path) as fd:
#        return from_file(
#            fd,
#            location=os.path.abspath(path),
#            base_url=base_url,
#            method=method,
#            endpoint=endpoint,
#            tag=tag,
#            app=app,
#            validate_schema=validate_schema,
#        )
#
#
#def from_uri(
#    uri,
#    base_url = None,
#    method = None,
#    endpoint = None,
#    tag = None,
#    **kwargs
#):
#    if 'validate_schema' in kwargs: validate_schema = kwargs['validate_schema']; del kwargs['validate_schema']
#    else: validate_schema =  True
#    if 'app' in kwargs: app = kwargs['app']; del kwargs['app']
#    else: app =  None
#    """Load a remote resource and parse to schema instance."""
#    kwargs.setdefault("headers", {}).setdefault("User-Agent", USER_AGENT)
#    response = requests.get(uri, **kwargs)
#    try:
#        response.raise_for_status()
#    except requests.HTTPError:
#        raise HTTPError(response=response, url=uri)
#    if base_url is None:
#        base_url = get_base_url(uri)
#    return from_file(
#        response.text,
#        location=uri,
#        base_url=base_url,
#        method=method,
#        endpoint=endpoint,
#        tag=tag,
#        app=app,
#        validate_schema=validate_schema,
#    )


def from_file(
    file,
    location = None,
    base_url = None,
    method = None,
    endpoint = None,
    tag = None, **_3to2kwargs):
    if 'validate_schema' in _3to2kwargs: validate_schema = _3to2kwargs['validate_schema']; del _3to2kwargs['validate_schema']
    else: validate_schema =  True
    if 'app' in _3to2kwargs: app = _3to2kwargs['app']; del _3to2kwargs['app']
    else: app =  None
    """Load a file content and parse to schema instance.

    `file` could be a file descriptor, string or bytes.
    """
    raw = yaml.load(file, StringDatesYAMLLoader)
    return from_dict(
        raw,
        location=location,
        base_url=base_url,
        method=method,
        endpoint=endpoint,
        tag=tag,
        app=app,
        validate_schema=validate_schema,
    )


def from_dict(
    raw_schema,
    location = None,
    base_url = None,
    method = None,
    endpoint = None,
    tag = None, **_3to2kwargs):
    if 'validate_schema' in _3to2kwargs: validate_schema = _3to2kwargs['validate_schema']; del _3to2kwargs['validate_schema']
    else: validate_schema =  True
    if 'app' in _3to2kwargs: app = _3to2kwargs['app']; del _3to2kwargs['app']
    else: app =  None
    """Get a proper abstraction for the given raw schema."""
    if "swagger" in raw_schema:
        _maybe_validate_schema(raw_schema, spec_schemas.SWAGGER_20, validate_schema)
        return SwaggerV20(
            raw_schema, location=location, base_url=base_url, method=method, endpoint=endpoint, tag=tag, app=app
        )

    if "openapi" in raw_schema:
        _maybe_validate_schema(raw_schema, spec_schemas.OPENAPI_30, validate_schema)
        return OpenApi30(
            raw_schema, location=location, base_url=base_url, method=method, endpoint=endpoint, tag=tag, app=app
        )
    raise ValueError("Unsupported schema type")


def _maybe_validate_schema(instance, schema, validate_schema):
    if validate_schema:
        try:
            jsonschema.validate(instance, schema)
        except TypeError:
            raise ValidationError("Invalid schema")


#def from_pytest_fixture(
#    fixture_name,
#    method = NOT_SET,
#    endpoint = NOT_SET,
#    tag = NOT_SET,
#):
#    """Needed for a consistent library API."""
#    return LazySchema(fixture_name, method=method, endpoint=endpoint, tag=tag)
#
#
#def from_wsgi(
#    schema_path,
#    app,
#    base_url = None,
#    method = None,
#    endpoint = None,
#    tag = None,
#    validate_schema = True,
#):
#    client = Client(app, WSGIResponse)
#    response = client.get(schema_path, headers={"User-Agent": USER_AGENT})
#    # Raising exception to provide unified behavior
#    # E.g. it will be handled in CLI - a proper error message will be shown
#    if 400 <= response.status_code < 600:
#        raise HTTPError(response=response, url=schema_path)
#    return from_file(
#        response.data,
#        location=schema_path,
#        base_url=base_url,
#        method=method,
#        endpoint=endpoint,
#        tag=tag,
#        app=app,
#        validate_schema=validate_schema,
#    )
#
#
#def get_loader_for_app(app):
#    if app.__class__.__module__.startswith("aiohttp."):
#        return from_aiohttp
#    return from_wsgi
#
#
#def from_aiohttp(
#    schema_path,
#    app,
#    base_url = None,
#    method = None,
#    endpoint = None,
#    tag = None, **_3to2kwargs):
#    if 'validate_schema' in _3to2kwargs: validate_schema = _3to2kwargs['validate_schema']; del _3to2kwargs['validate_schema']
#    else: validate_schema =  True
#    from .extra._aiohttp import run_server  # pylint: disable=import-outside-toplevel
#
#    port = run_server(app)
#    app_url = "http://127.0.0.1:{port}/".format(port=port)
#    url = urljoin(app_url, schema_path)
#    if not base_url:
#        base_url = app_url
#    return from_uri(url, base_url=base_url, method=method, endpoint=endpoint, tag=tag, validate_schema=validate_schema)
#
#
## Backward compatibility
#class Parametrizer(object):
#    from_path = deprecated(from_path, "`Parametrizer.from_path` is deprecated, use `schemathesis.from_path` instead.")
#    from_uri = deprecated(from_uri, "`Parametrizer.from_uri` is deprecated, use `schemathesis.from_uri` instead.")
