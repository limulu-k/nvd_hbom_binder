"""Survive a Joern server that stops answering, without losing the step.

Step 4 issues four queries per function against a long-lived Joern server. Any
one of them can stop coming back: the observed case on tensorflow was a
millisecond-scale id lookup that hung for the full 1800 s query timeout, right
after the three expensive queries on the same 78-line function had returned.
Keepalive is disabled on that websocket (see ``cpgqls_client/client.py``), so a
completion notification that never arrives is never noticed either - the query
timeout is the only bound.

Upstream lets that exception escape, which kills the whole step. On tensorflow
that discarded 812 of 866 function pairs' worth of remaining work and left the
run with no way forward, because a rerun hits the same function again.

This module makes the failure recoverable in two moves:

* the offending function is recorded in a ledger under ``Joern_result/``, which
  outlives the process but not the repository, and
* the step exits with :data:`QUERY_TIMEOUT_EXIT` so the cycle can tell "Joern
  stopped answering" apart from a genuine crash, restart the server, and run the
  step again - completed functions are skipped through their ``mergeRES`` file.

A function that times out again after a fresh server is not a server problem;
:func:`query_timeout_exhausted` then skips it for good so the remaining
functions still get analysed. That trades one function's verdicts for the other
865, and the ledger says exactly which one was given up on.
"""

from __future__ import annotations

import asyncio
import json
import os

# Distinct from 1, which any Python traceback produces: it means the server
# stopped answering, not that the analysis found something wrong.
QUERY_TIMEOUT_EXIT = 42

# A step that ends this way did its work and stopped on purpose, because the
# server it depends on is getting heavy. Distinct from QUERY_TIMEOUT_EXIT: that
# one reports damage, this one prevents it.
RECYCLE_EXIT = 43

_LEDGER_NAME = "query_timeouts.json"
_ledger_path = None

try:  # pragma: no cover - exercised only when websockets is installed
    from websockets.exceptions import WebSocketException as _WebSocketException
except ImportError:  # pragma: no cover
    _WebSocketException = None

try:  # pragma: no cover - the client posts the query over HTTP
    from requests.exceptions import RequestException as _RequestException
except ImportError:  # pragma: no cover
    _RequestException = None

# A query that never came back, a socket that died under it, or a server that
# went away - the response is the same for all three: restart and retry.
# Deliberately not plain OSError: create_cpg also writes its results to disk,
# and a failure there is a real error that must not be mistaken for a sulking
# server and retried forever.
TRANSIENT_QUERY_ERRORS: tuple[type[BaseException], ...] = tuple(
    error
    for error in (
        asyncio.TimeoutError,
        TimeoutError,
        ConnectionError,
        _WebSocketException,
        _RequestException,
    )
    if isinstance(error, type)
)


def set_ledger_dir(directory: str) -> None:
    """Point the ledger at this run's ``Joern_result/``.

    That directory is purged per repository, so the ledger never carries an
    attempt count from one repository into the next, and survives the step
    reruns within one repository, which is exactly the lifetime wanted.
    """

    global _ledger_path
    os.makedirs(directory, exist_ok=True)
    _ledger_path = os.path.join(directory, _LEDGER_NAME)


def _read() -> dict[str, int]:
    if not _ledger_path or not os.path.exists(_ledger_path):
        return {}
    try:
        with open(_ledger_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def record_query_timeout(name: str) -> int:
    """Count one lost query against ``name`` and return the new attempt count."""
    ledger = _read()
    attempts = int(ledger.get(name, 0)) + 1
    ledger[name] = attempts
    if _ledger_path:
        with open(_ledger_path, "w", encoding="utf-8") as handle:
            json.dump(ledger, handle, indent=2, sort_keys=True)
    return attempts


def query_timeout_exhausted(name: str, limit: int = 2) -> bool:
    """Whether ``name`` already used up its attempts and must be skipped.

    The default of 2 gives every function one attempt on a freshly restarted
    server. Hanging twice, once on a server holding nothing but this function,
    is evidence about the function rather than about the server.
    """

    return int(_read().get(name, 0)) >= limit


def abandoned_functions(limit: int = 2) -> list[str]:
    """Functions given up on, so the caller can report them rather than count them."""
    return sorted(name for name, count in _read().items() if int(count) >= limit)


# ------------------------------------------------------------------ pressure
#
# Each successfully analysed old/new function project is deleted after its CPG
# files are written, but that does not reset Joern's long-lived Scala REPL.  In
# practice its compiler can still accumulate enough hidden state to overflow a
# worker thread's stack even while the workspace holds no completed projects.
# Count completed function pairs as the primary pressure signal; project count
# and RSS remain useful safety nets for interrupted imports and heap growth.
#
# So the step measures the server it is using and stops on its own terms while
# everything is still healthy. Yielding is nearly free now that a rerun skips
# every function already merged, which is what makes prevention affordable.

_JOERN_PROCESS = "io.joern.joerncli.console.ReplBridge"
_completed_functions = 0


def joern_project_count(workspace: str = "workspace") -> int:
    """How many projects the server's store holds. -1 when it cannot be read."""
    try:
        return sum(1 for entry in os.scandir(workspace) if entry.is_dir())
    except OSError:
        return -1


def joern_rss_mb() -> int:
    """Resident size of the Joern JVM in MB. -1 when it cannot be read."""
    import subprocess

    try:
        found = subprocess.run(
            ["pgrep", "-f", _JOERN_PROCESS], capture_output=True, text=True, timeout=10
        )
        pids = [line for line in found.stdout.split() if line.isdigit()]
        if not pids:
            return -1
        with open(f"/proc/{pids[-1]}/status", "r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) // 1024
    except (OSError, ValueError, subprocess.SubprocessError):
        return -1
    return -1


def recycle_reason(workspace: str = "workspace") -> str:
    """Record one completed function pair and decide whether to restart Joern.

    This must be called exactly once after a function pair's merged result has
    been committed. The counter is intentionally process-local: exit 43 starts
    a new step process together with a new Joern process, so both lifetimes
    begin at zero again.

    Limits come from the environment so the cycle stays the single place that
    decides policy. 0 disables a limit, which is also what the cycle sets when
    it has no way to restart the server and the step should just carry on.
    """

    global _completed_functions
    _completed_functions += 1
    max_functions = int(os.environ.get("CLOVERY_MAX_JOERN_FUNCTIONS", "0") or 0)
    max_projects = int(os.environ.get("CLOVERY_MAX_JOERN_PROJECTS", "0") or 0)
    max_rss = int(os.environ.get("CLOVERY_MAX_JOERN_RSS_MB", "0") or 0)
    if max_functions > 0 and _completed_functions >= max_functions:
        return (
            f"{_completed_functions} function pairs completed "
            f"(limit {max_functions})"
        )
    if max_projects > 0:
        projects = joern_project_count(workspace)
        if projects >= max_projects:
            return f"{projects} projects held (limit {max_projects})"
    if max_rss > 0:
        rss = joern_rss_mb()
        if rss >= max_rss:
            return f"Joern at {rss} MB resident (limit {max_rss} MB)"
    return ""
