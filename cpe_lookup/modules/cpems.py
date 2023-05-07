from typing import Union

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

from ..config import get_settings
from ..models import CPE, CPEDeviceInfo

log = structlog.get_logger()


async def get_cpe(cid: str) -> Union[CPEDeviceInfo, None]:
    endpoint = f"{get_settings().cpe_status_endpoint}/{cid}"
    async with AsyncClient(timeout=get_settings().api_timeout) as client:
        try:
            response = await client.get(endpoint)
            log.msg(
                "Get CPE Info",
                url=response.url,
                status_code=response.status_code,
            )

            response.raise_for_status()
            cpe_info = CPEDeviceInfo(**response.json())

        except (RequestError, ReadTimeout, ConnectTimeout) as exc:
            log.msg(
                "CPE info API request failed to upstream.",
                error=exc,
                **context.data,
            )
            raise HTTPException(504, detail="CPE info API request failed to upstream.")
        except HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return None, response.url, response.status_code
            else:
                raise HTTPException(exc.response.status_code, detail=exc.response.text)
    return CPE.FromDeviceInfo(cpe_info), response.url, response.status_code
