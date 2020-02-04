import os
import shutil
import time
from typing import Callable, Iterable, List

import attr
import hypothesis

from ..models import Endpoint, Status, TestResultSet
from ..schemas import BaseSchema


@attr.s(slots=True)  # pragma: no mutate
class ExecutionContext:
    """Storage for the current context of the execution."""

    hypothesis_output = attr.ib(factory=list, type=List[str])  # pragma: no mutate
    workers_num = attr.ib(default=1, type=int)  # pragma: no mutate
    endpoints_processed = attr.ib(default=0, type=int)  # pragma: no mutate
    current_line_length = attr.ib(default=0, type=int)  # pragma: no mutate
    terminal_size = attr.ib(factory=shutil.get_terminal_size, type=os.terminal_size)  # pragma: no mutate


@attr.s()  # pragma: no mutate
class ExecutionEvent:
    results = attr.ib(type=TestResultSet)  # pragma: no mutate
    schema = attr.ib(type=BaseSchema)  # pragma: no mutate


@attr.s(slots=True)  # pragma: no mutate
class Initialized(ExecutionEvent):
    """Runner is initialized, settings are prepared, requests session is ready."""

    checks = attr.ib(type=Iterable[Callable])  # pragma: no mutate
    hypothesis_settings = attr.ib(type=hypothesis.settings)  # pragma: no mutate
    start_time = attr.ib(factory=time.time, type=float)


@attr.s(slots=True)  # pragma: no mutate
class BeforeExecution(ExecutionEvent):
    endpoint = attr.ib(type=Endpoint)  # pragma: no mutate


@attr.s(slots=True)  # pragma: no mutate
class AfterExecution(ExecutionEvent):
    endpoint = attr.ib(type=Endpoint)  # pragma: no mutate
    status = attr.ib(type=Status)  # pragma: no mutate
    hypothesis_output = attr.ib(factory=list, type=List[str])  # pragma: no mutate


@attr.s(slots=True)  # pragma: no mutate
class Interrupted(ExecutionEvent):
    pass


@attr.s(slots=True)  # pragma: no mutate
class Finished(ExecutionEvent):
    running_time = attr.ib(type=float)
