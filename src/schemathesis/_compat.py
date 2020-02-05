from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
# pylint: disable=unused-import
from future import standard_library
standard_library.install_aliases()
from contextlib import contextmanager
from typing import Generator
from warnings import catch_warnings, simplefilter


@contextmanager
def handle_warnings():
    try:
        from hypothesis.errors import NonInteractiveExampleWarning  # pylint: disable=import-outside-toplevel

        with catch_warnings():
            simplefilter("ignore", NonInteractiveExampleWarning)
            yield
    except ImportError:
        yield


try:
    from importlib import metadata
except ImportError:
    import importlib_metadata as metadata  # type: ignore
