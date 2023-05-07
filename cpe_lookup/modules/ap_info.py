import structlog
from fastapi import HTTPException
from httpx import (
    AsyncClient,
    ConnectError,
    ConnectTimeout,
    HTTPStatusError,
    ReadTimeout,
    RequestError,
)
from starlette_context import context

from cpe_lookup.config import get_settings
from cpe_lookup.models import AP, APDeviceInfo

log = structlog.get_logger()


async def get_ap_info(bssid: str):
    endpoint = get_settings().ap_info_endpoint.format(bssid=bssid)
    async with AsyncClient(timeout=get_settings().api_timeout) as client:
        try:
            resp = await client.get(endpoint)
            log.msg(
                "Get AP Info",
                url=resp.url,
                status_code=resp.status_code,
            )
            resp.raise_for_status()
            if resp.status_code == 200:
                json_resp = resp.json()
                data = json_resp.get("ap_infos")[0]
                ap_info = APDeviceInfo(**data)

        except (RequestError, ReadTimeout, ConnectTimeout) as exc:
            log.msg(
                "Wireless uplink info API request failed to upstream.",
                error=exc,
                **context.data,
            )
            raise HTTPException(
                504, detail="Wireless uplink info API request failed to upstream."
            )
        except HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return None, resp.url, resp.status_code
            else:
                raise HTTPException(exc.response.status_code, detail=exc.response.text)
        except ConnectError:
            raise HTTPException(500, "All connection attempts failed")

    return AP.FromDeviceInfo(ap_info), resp.url, resp.status_code
