from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
from future import standard_library
standard_library.install_aliases()
import click

from ...runner import events
from . import default


def handle_after_execution(context, event):
    context.endpoints_processed += 1
    default.display_execution_result(context, event)
    if context.endpoints_processed == event.schema.endpoints_count:
        click.echo()


def handle_event(context, event):
    """Short output style shows single symbols in the progress bar.

    Otherwise, identical to the default output style.
    """
    if isinstance(event, events.Initialized):
        default.handle_initialized(context, event)
    if isinstance(event, events.AfterExecution):
        context.hypothesis_output.extend(event.hypothesis_output)
        handle_after_execution(context, event)
    if isinstance(event, events.Finished):
        default.handle_finished(context, event)
    if isinstance(event, events.Interrupted):
        default.handle_interrupted(context, event)
