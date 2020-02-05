from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
from builtins import map
from future import standard_library
standard_library.install_aliases()
import re
from typing import List, Optional

from .types import Filter
from .utils import force_tuple


def should_skip_method(method, pattern):
    if pattern is None:
        return False
    patterns = force_tuple(pattern)
    return method.upper() not in map(str.upper, patterns)


def should_skip_endpoint(endpoint, pattern):
    if pattern is None:
        return False
    patterns = force_tuple(pattern)
    return not any(re.search(item, endpoint) for item in patterns)


def should_skip_by_tag(tags, pattern):
    if pattern is None:
        return False
    if not tags:
        return True
    patterns = force_tuple(pattern)
    return not any(re.search(item, tag) for item in patterns for tag in tags)
