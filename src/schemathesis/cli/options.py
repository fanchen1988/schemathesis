from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
from builtins import super
from builtins import int
from future import standard_library
standard_library.install_aliases()
from builtins import object
from enum import Enum
from typing import List, Optional, Type, Union

import click


class CSVOption(click.Choice):
    def __init__(self, choices):
        self.enum = choices
        super().__init__(tuple(choices.__members__))

    def convert(
        self, value, param, ctx
    ):
        items = [item for item in value.split(",") if item]
        invalid_options = set(items) - set(self.choices)
        if not invalid_options and items:
            return [self.enum[item] for item in items]
        # Sort to keep the error output consistent with the passed values
        sorted_options = ", ".join(sorted(invalid_options, key=items.index))
        available_options = ", ".join(self.choices)
        self.fail("invalid choice(s): {sorted_options}. Choose from {available_options}".format(sorted_options=sorted_options, available_options=available_options))


class NotSet(object):
    pass


not_set = NotSet()


class OptionalInt(click.types.IntParamType):
    def convert(  # type: ignore
        self, value, param, ctx
    ):
        if value == "None":
            return not_set
        try:
            return int(value)
        except (ValueError, UnicodeError):
            self.fail("%s is not a valid integer or None" % value, param, ctx)
