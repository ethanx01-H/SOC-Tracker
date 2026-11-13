"""Guard the concurrency fix: no request handler may run on the event loop.

Every handler talks to the database synchronously and the login path runs a
240k-iteration PBKDF2. Declared ``async def``, those calls block the single
event loop for the whole team; declared ``def``, Starlette runs them in its
thread pool. This test fails if an ``async def`` handler comes back.
"""

import inspect

import pytest
from fastapi.routing import APIRoute

from main import app
from soc_tracker.services import evidence_service


def _endpoints(routes=None):
    """Walk the app's routes.

    Newer FastAPI wraps included routers in ``_IncludedRouter``, which exposes
    the real routes through ``original_router`` rather than ``routes``.
    """
    for route in app.routes if routes is None else routes:
        if isinstance(route, APIRoute):
            yield route.path, route.endpoint
        elif hasattr(route, "original_router"):
            yield from _endpoints(route.original_router.routes)
        elif hasattr(route, "routes"):
            yield from _endpoints(route.routes)


def test_no_endpoint_is_declared_async():
    offenders = [
        path for path, endpoint in _endpoints()
        if inspect.iscoroutinefunction(endpoint)
    ]
    assert not offenders, f"these handlers block the event loop: {offenders}"


def test_every_route_was_examined():
    """A guard against the check above silently matching nothing."""
    assert len(list(_endpoints())) > 20


def test_upload_reader_is_synchronous():
    assert not inspect.iscoroutinefunction(evidence_service.read_upload)


def test_handlers_run_in_the_threadpool():
    """A sync handler is dispatched with run_in_threadpool by Starlette."""
    from starlette.concurrency import run_in_threadpool

    assert inspect.iscoroutinefunction(run_in_threadpool)
