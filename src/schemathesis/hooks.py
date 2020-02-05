from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
from future import standard_library
standard_library.install_aliases()
from typing import Optional

from .constants import HookLocation
from .types import Hook

GLOBAL_HOOKS = {}


def register(place, hook):
    key = HookLocation[place]
    GLOBAL_HOOKS[key] = hook


def get_hook(place):
    key = HookLocation[place]
    return GLOBAL_HOOKS.get(key)


def unregister_all():
    GLOBAL_HOOKS.clear()
