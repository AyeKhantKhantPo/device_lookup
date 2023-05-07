from typing import Dict, List

import structlog
from fastapi import FastAPI

from .config import Settings, get_settings
from .eventlog import error_event_handler, json_event_encoder
from .middleware import chain_http_filters
from .routes import ap, cpe, customerid, fiber, internal, rt, subscription

structlog.configure(
    processors=[
        structlog.processors.format_exc_info,
        structlog.processors.TimeStamper(),
        error_event_handler,
        json_event_encoder,
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.BoundLogger,
    cache_logger_on_first_use=True,
)


def get_openapi_tags() -> List[Dict[str, str]]:
    metadata = []
    metadata.extend(internal.openapi_tags)
    metadata.extend(subscription.openapi_tags)
    metadata.extend(cpe.openapi_tags)
    metadata.extend(customerid.openapi_tags)
    metadata.extend(ap.openapi_tags)
    metadata.extend(rt.openapi_tags)
    return metadata


def create_app(app_name: str, app_version: str) -> FastAPI:
    settings: Settings = get_settings()
    app = FastAPI(
        root_path=settings.app_root_path,
        title=app_name,
        version=app_version,
        openapi_tags=get_openapi_tags(),
    )
    chain_http_filters(app)
    app.include_router(internal.router, prefix=settings.internal_routes_prefix)
    app.include_router(subscription.router, prefix="/cpes")
    app.include_router(cpe.router, prefix="/cpes")
    app.include_router(customerid.router, prefix="/customers")
    app.include_router(ap.router, prefix="/uplink/wireless")
    app.include_router(fiber.router, prefix="/uplink/fiber")
    app.include_router(rt.router, prefix="/tickets/cpe")

    return app
