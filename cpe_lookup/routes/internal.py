import structlog
from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse

log = structlog.get_logger()


openapi_tags = [
    {
        "name": "internal-routes",
        "description": "Endpoints for internal operations such as active healthchecking from control-plane.",
    }
]

router = APIRouter(tags=["internal-routes"])


@router.get(
    "/server_info",
    response_class=PlainTextResponse,
    responses={
        200: {
            "description": "Application name and version",
            "content": {"text/plain": {"example": "cpe_lookup/0.1.0"}},
        }
    },
)
async def server_info(request: Request):
    return PlainTextResponse(f"{request.app.title}/{request.app.version}", 200)


@router.get("/healthcheck", response_class=PlainTextResponse)
async def healthcheck():
    return PlainTextResponse("OK", 200)
