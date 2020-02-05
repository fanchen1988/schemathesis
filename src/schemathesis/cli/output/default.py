from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
from builtins import map
from builtins import str
from future import standard_library
standard_library.install_aliases()
import logging
import os
import platform
import shutil
from typing import Any, Dict, List, Optional, Set, Tuple, Union, cast

import click
from attr import Attribute
from hypothesis import settings

from ..._compat import metadata
from ...constants import __version__
from ...models import Case, Check, Status, TestResult, TestResultSet
from ...runner import events
from .. import utils


def get_terminal_width():
    return shutil.get_terminal_size().columns


def display_section_name(title, separator = "=", **kwargs):
    """Print section name with separators in terminal with the given title nicely centered."""
    message = " {title} ".format(title=title).center(get_terminal_width(), separator)
    kwargs.setdefault("bold", True)
    click.secho(message, **kwargs)


def display_subsection(result, color = "red"):
    section_name = "{method}: {path}".format(method=result.endpoint.method, path=result.endpoint.path)
    display_section_name(section_name, "_", fg=color)


def get_percentage(position, length):
    """Format completion percentage in square brackets."""
    percentage_message = "{perct}%".format(perct=position * 100 // length).rjust(4)
    return "[{percentage_message}]".format(percentage_message=percentage_message)


def display_execution_result(context, event):
    """Display an appropriate symbol for the given event's execution result."""
    symbol, color = {Status.success: (".", "green"), Status.failure: ("F", "red"), Status.error: ("E", "red")}[
        event.status
    ]
    context.current_line_length += len(symbol)
    click.secho(symbol, nl=False, fg=color)


def display_percentage(context, event):
    """Add the current progress in % to the right side of the current line."""
    padding = 1
    current_percentage = get_percentage(context.endpoints_processed, event.schema.endpoints_count)
    styled = click.style(current_percentage, fg="cyan")
    # Total length of the message so it will fill to the right border of the terminal minus padding
    length = get_terminal_width() - context.current_line_length + len(styled) - len(current_percentage) - padding
    template = "{{:>{length}}}".format(length=length)
    click.echo(template.format(styled))


def display_summary(event):
    message, color, status_code = get_summary_output(event)
    display_section_name(message, fg=color)
    raise click.exceptions.Exit(status_code)


def get_summary_message_parts(results):
    parts = []
    passed = results.passed_count
    if passed:
        parts.append("{passed} passed".format(passed=passed))
    failed = results.failed_count
    if failed:
        parts.append("{failed} failed".format(failed=failed))
    errored = results.errored_count
    if errored:
        parts.append("{errored} errored".format(errored=errored))
    return parts


def get_summary_output(event):
    parts = get_summary_message_parts(event.results)
    if not parts:
        message = "Empty test suite"
        color = "yellow"
        status_code = 0
    else:
        message = '{parts} in {running_time:.2f}s'.format(parts=", ".join(parts), running_time=event.running_time)
        if event.results.has_failures or event.results.has_errors:
            color = "red"
            status_code = 1
        else:
            color = "green"
            status_code = 0
    return message, color, status_code


def display_hypothesis_output(hypothesis_output):
    """Show falsifying examples from Hypothesis output if there are any."""
    if hypothesis_output:
        display_section_name("HYPOTHESIS OUTPUT")
        output = "\n".join(hypothesis_output)
        click.secho(output, fg="red")


def display_errors(results):
    """Display all errors in the test run."""
    if not results.has_errors:
        return

    display_section_name("ERRORS")
    for result in results:
        if not result.has_errors:
            continue
        display_single_error(result)


def display_single_error(result):
    display_subsection(result)
    for error, example in result.errors:
        message = utils.format_exception(error)
        click.secho(message, fg="red")
        if example is not None:
            display_example(example, seed=result.seed)


def display_failures(results):
    """Display all failures in the test run."""
    if not results.has_failures:
        return
    relevant_results = [result for result in results if not result.is_errored]
    if not relevant_results:
        return
    display_section_name("FAILURES")
    for result in relevant_results:
        if not result.has_failures:
            continue
        display_failures_for_single_test(result)


def display_failures_for_single_test(result):
    """Display a failure for a single method / endpoint."""
    display_subsection(result)
    checks = _get_unique_failures(result.checks)
    for idx, check in enumerate(checks, 1):
        if check.message:
            message = "{idx}. {message}".format(idx=idx, message=check.message)
        else:
            message = None
        example = cast(Case, check.example)  # filtered in `_get_unique_failures`
        display_example(example, check.name, message, result.seed)
        # Display every time except the last check
        if idx != len(checks):
            click.echo("\n")


def _get_unique_failures(checks):
    """Return only unique checks that should be displayed in the output."""
    seen = set()
    unique_checks = []
    for check in reversed(checks):
        # There are also could be checks that didn't fail
        if check.example is not None and check.value == Status.failure and (check.name, check.message) not in seen:
            unique_checks.append(check)
            seen.add((check.name, check.message))
    return unique_checks


def display_example(
    case, check_name = None, message = None, seed = None
):
    if message is not None:
        click.secho(message, fg="red")
        click.echo()
    output = {
        make_verbose_name(attribute): getattr(case, attribute.name)
        for attribute in Case.__attrs_attrs__  # type: ignore
        if attribute.name not in ("path", "method", "base_url", "app", "endpoint")
    }
    max_length = max(map(len, output))
    template = "{{:<{max_length}}} : {{}}".format(max_length=max_length)
    if check_name is not None:
        click.secho(template.format("Check", check_name), fg="red")
    for key, value in output.items():
        if (key == "Body" and value is not None) or value not in (None, {}):
            click.secho(template.format(key, value), fg="red")
    click.echo()
    click.secho("Run this Python code to reproduce this failure: \n\n    {code}".format(code=case.get_code_to_reproduce()), fg="red")
    if seed is not None:
        click.secho("\nOr add this option to your command line parameters: --hypothesis-seed={seed}".format(seed=seed), fg="red")


def make_verbose_name(attribute):
    return attribute.name.capitalize().replace("_", " ")


def display_application_logs(statistic):
    """Print logs captured during the application run."""
    if not statistic.has_logs:
        return
    display_section_name("APPLICATION LOGS")
    formatter = logging.Formatter("[%(asctime)s] %(levelname)s in %(module)s: %(message)s")
    for result in statistic:
        if not result.has_logs:
            continue
        display_single_log(result, formatter)


def display_single_log(result, formatter):
    display_subsection(result, None)
    formatted = [formatter.format(record) for record in result.logs]
    click.echo("\n\n".join(formatted))


def display_statistic(statistic):
    """Format and print statistic collected by :obj:`models.TestResult`."""
    display_section_name("SUMMARY")
    click.echo()
    total = statistic.total
    if statistic.is_empty or not total:
        click.secho("No checks were performed.", bold=True)
        return

    padding = 20
    col1_len = max(map(len, total.keys())) + padding
    col2_len = len(str(max(total.values(), key=lambda v: v["total"])["total"])) * 2 + padding
    col3_len = padding

    template = "{{:{col1_len}}}{{:{col2_len}}}{{:{col3_len}}}".format(col1_len=col1_len, col2_len=col2_len, col3_len=col3_len)

    for check_name, results in total.items():
        display_check_result(check_name, results, template)


def display_check_result(check_name, results, template):
    """Show results of single check execution."""
    if Status.failure in results:
        verdict = "FAILED"
        color = "red"
    else:
        verdict = "PASSED"
        color = "green"
    success = results.get(Status.success, 0)
    total = results.get("total", 0)
    click.echo(
        template.format(
            click.style(check_name, bold=True), "{success} / {total} passed".format(success=success, total=total), click.style(verdict, fg=color, bold=True)
        )
    )


def handle_initialized(context, event):
    """Display information about the test session."""
    display_section_name("Schemathesis test session starts")
    versions = (
        "platform {system} -- "
        "Python {py_version}, "
        "schemathesis-{version}, "
        "hypothesis-{hy_version}, "
        "hypothesis_jsonschema-{hyjs_version}, "
        "jsonschema-{js_version}"
    ).format(system=platform.system(), py_version=platform.python_version(), version=__version__, hy_version=metadata.version('hypothesis'), hyjs_version=metadata.version('hypothesis_jsonschema'), js_version=metadata.version('jsonschema'))
    click.echo(versions)
    click.echo("rootdir: {cwd}".format(cwd=os.getcwdu()))
    click.echo(
        "hypothesis profile '{cur_profile}' "  # type: ignore
        "-> {changed}"
    ).format(cur_profile=settings._current_profile, changed=settings.get_profile(settings._current_profile).show_changed())
    if event.schema.location is not None:
        click.echo("Schema location: {location}".format(location=event.schema.location))
    if event.schema.base_url is not None:
        click.echo("Base URL: {base_url}".format(base_url=event.schema.base_url))
    click.echo("Specification version: {verbose_name}".format(verbose_name=event.schema.verbose_name))
    click.echo("Workers: {workers_num}".format(workers_num=context.workers_num))
    click.secho("collected endpoints: {endpoints_count}".format(endpoints_count=event.schema.endpoints_count), bold=True)
    if event.schema.endpoints_count >= 1:
        click.echo()


def handle_before_execution(context, event):
    """Display what method / endpoint will be tested next."""
    message = "{method} {path} ".format(method=event.endpoint.method, path=event.endpoint.path)
    context.current_line_length = len(message)
    click.echo(message, nl=False)


def handle_after_execution(context, event):
    """Display the execution result + current progress at the same line with the method / endpoint names."""
    context.endpoints_processed += 1
    display_execution_result(context, event)
    display_percentage(context, event)


def handle_finished(context, event):
    """Show the outcome of the whole testing session."""
    click.echo()
    display_hypothesis_output(context.hypothesis_output)
    display_errors(event.results)
    display_failures(event.results)
    display_application_logs(event.results)
    display_statistic(event.results)
    click.echo()
    display_summary(event)


def handle_interrupted(context, event):
    click.echo()
    display_section_name("KeyboardInterrupt", "!", bold=False)


def handle_event(context, event):
    """Choose and execute a proper handler for the given event."""
    if isinstance(event, events.Initialized):
        handle_initialized(context, event)
    if isinstance(event, events.BeforeExecution):
        handle_before_execution(context, event)
    if isinstance(event, events.AfterExecution):
        context.hypothesis_output.extend(event.hypothesis_output)
        handle_after_execution(context, event)
    if isinstance(event, events.Finished):
        handle_finished(context, event)
    if isinstance(event, events.Interrupted):
        handle_interrupted(context, event)
