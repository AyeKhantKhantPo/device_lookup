import structlog
from fastapi import HTTPException
from httpx import (
    AsyncClient,
    ConnectTimeout,
    HTTPStatusError,
    ReadTimeout,
    RequestError,
)
from starlette_context import context

from cpe_lookup.config import Settings, get_settings
from cpe_lookup.models import FiberInfo

log = structlog.get_logger()
settings: Settings = get_settings()


async def get_fiber_uplink(cid: str):
    headers = {
        "authorization": settings.fiber_auth_key,
        "x-username": settings.fiber_auth_user,
    }

    endpoint = settings.fiber_uplink_endpoint.format(cid=cid)

    async with AsyncClient(
        headers=headers, verify=False, timeout=settings.api_timeout
    ) as client:
        try:
            response = await client.get(endpoint)
            log.msg(
                "Get fiber uplink informations and status",
                url=response.url,
                status_code=response.status_code,
            )
            response.raise_for_status()
            data = response.json()
            olt = data.get("olt")
            if olt:
                olt_lastseen = olt.get("last_seen", None)
                if olt_lastseen is not None:
                    data["olt"]["last_seen"] = olt_lastseen.split(".")[0]
            status = data.get("status")
            if status:
                status_lastseen = status.get("last_seen", None)
                if status_lastseen is not None:
                    data["status"]["last_seen"] = status_lastseen.split(".")[0]

            fiber_info = FiberInfo(**data)

        except (RequestError, ReadTimeout, ConnectTimeout) as exc:
            log.msg(
                "Fiber uplink info API request failed to OLTMS",
                error=exc,
                **context.data,
            )
            raise HTTPException(
                504, detail="Fiber uplink info API request failed to upstream"
            )
        except HTTPStatusError as exc:
            log.msg(
                "Fiber uplink info API response not successful",
                error=exc,
                **context.data,
            )
            if exc.response.status_code == 404:
                return None, response.url, response.status_code
            else:
                raise HTTPException(exc.response.status_code, detail=exc.response.text)

    return fiber_info, response.url, response.status_code
