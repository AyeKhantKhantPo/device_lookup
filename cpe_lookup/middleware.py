import re
from typing import Any, Optional, Pattern
from uuid import uuid4

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.datastructures import MutableHeaders
from starlette_context import context
from starlette_context.errors import MiddleWareValidationError
from starlette_context.middleware import RawContextMiddleware
from starlette_context.plugins import Plugin

from cpe_lookup.config import get_settings

log = structlog.get_logger()

rt_route = get_settings().rt_route
rt_route_pattern: Pattern = re.compile(
    r"^{rt_route}(?P<cid>[a-zA-Z]{{2,3}}[0-9]{{6}}).*$".format(rt_route=rt_route)
)
fiber_route = get_settings().fiber_route
fiber_route_pattern: Pattern = re.compile(
    r"^{fiber_route}(?P<cid>[a-zA-Z]{{2,3}}[0-9]{{6}}).*$".format(
        fiber_route=fiber_route
    )
)


class XRequestID(Plugin):
    key = "x-request-id"

    async def extract_value_from_header_by_key(self, request) -> str:
        value = await super().extract_value_from_header_by_key(request)
        if not value:
            value = uuid4()
        return str(value)

    async def enrich_response(self, arg) -> None:
        request_id = str(context.get("x-request-id"))

        # for ContextMiddleware
        # if isinstance(arg, Response):
        #     arg.headers[self.key] = request_id

        # for RawContextMiddleware
        if arg["type"] == "http.response.start":
            headers = MutableHeaders(scope=arg)
            headers.append(self.key, request_id)


class XForwardedFor(Plugin):
    key = "x-forwarded-for"


class UserAgent(Plugin):
    key = "user-agent"


class FeatureRoutingPlugin(Plugin):
    key = "x-route"

    async def process_request(self, request: Request) -> Optional[Any]:
        route_path = request.url.path
        rt_match = rt_route_pattern.match(route_path)
        fiber_match = fiber_route_pattern.match(route_path)
        if rt_match:
            rt_feature_enabled = get_settings().rt_feature_enabled

            if not rt_feature_enabled:
                log.msg("Tickets service feature is disabled.")
                response = JSONResponse(
                    status_code=503,
                    content={"reason": "Tickets service feature is disabled."},
                )
                raise MiddleWareValidationError(
                    "Tickets service feature is disabled.", error_response=response
                )
            return "Tickets service feature is enabled."
        elif fiber_match:
            fiber_feature_enabled = get_settings().fiber_feature_enabled

            if not fiber_feature_enabled:
                log.msg("Fiber service feature is disabled.")
                response = JSONResponse(
                    status_code=503,
                    content={"reason": "Fiber service feature is disabled."},
                )
                raise MiddleWareValidationError(
                    "Fiber service feature is disabled.", error_response=response
                )
            return "Fiber service feature is enabled."


def cors_middleware(app: FastAPI) -> None:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


def context_middleware(app: FastAPI) -> None:
    app.add_middleware(
        RawContextMiddleware,
        plugins=(XRequestID(), XForwardedFor(), UserAgent(), FeatureRoutingPlugin()),
    )


def chain_http_filters(app: FastAPI) -> None:
    cors_middleware(app)
    context_middleware(app)
