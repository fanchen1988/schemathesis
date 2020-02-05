"""A Hypothesis extension for JSON schemata.

The only public API is `from_schema`; check the docstring for details.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from future import standard_library
standard_library.install_aliases()
__version__ = "0.11.1"
__all__ = ["from_schema"]

from ._from_schema import from_schema
