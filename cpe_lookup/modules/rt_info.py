import structlog
from fastapi import HTTPException
from httpx import AsyncClient, ConnectTimeout, ReadTimeout, WriteTimeout
from pydantic import Json

from ..config import get_settings

log = structlog.get_logger()


async def get_tkt_info(cid: str) -> Json:
    token = get_settings().rt_token
    endpoint = get_settings().rt_tkt_endpoint.format(token=token, cid=cid)
    try:
        async with AsyncClient(timeout=get_settings().api_timeout) as client:
            resp = await client.get(endpoint)
            resp.raise_for_status()

            return resp

    except (ConnectTimeout, WriteTimeout, ReadTimeout) as e:
        log.msg("TKT Info Connect Timeout", error=e)
        raise HTTPException(504, "TKT connection timeout")


async def get_asset_info(cid: str) -> Json:
    token = get_settings().rt_token
    endpoint = get_settings().rt_asset_endpoint.format(token=token, cid=cid)
    try:
        async with AsyncClient(timeout=get_settings().api_timeout) as client:
            resp = await client.get(endpoint)
            resp.raise_for_status()
            return resp

    except (ConnectTimeout, WriteTimeout, ReadTimeout) as e:
        log.msg("Asset Info Connect Timeout", error=e)
        raise HTTPException(504, "Asset connection timeout")
