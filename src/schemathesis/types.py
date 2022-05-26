from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
from future import standard_library
standard_library.install_aliases()
from builtins import object
from typing import Any, Callable, Dict, List, NewType, Set, Tuple, Union

from hypothesis.strategies import SearchStrategy

Schema = NewType("Schema", Dict[str, Any])  # pragma: no mutate

Query = Dict[str, Any]  # pragma: no mutate
Body = Union[Dict[str, Any], bytes]  # pragma: no mutate
PathParameters = Dict[str, Any]  # pragma: no mutate
Headers = Dict[str, Any]  # pragma: no mutate
Cookies = Dict[str, Any]  # pragma: no mutate
FormData = Dict[str, Any]  # pragma: no mutate


class NotSet(object):
    pass


# A filter for endpoint / method
Filter = Union[str, List[str], Tuple[str], Set[str], NotSet]  # pragma: no mutate

Hook = Callable[[SearchStrategy], SearchStrategy]
