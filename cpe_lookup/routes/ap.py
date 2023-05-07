import json
import re
from datetime import datetime

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from httpx import (
    ConnectError,
    ConnectTimeout,
    HTTPStatusError,
    ReadTimeout,
    RequestError,
)
from redis.exceptions import ConnectionError

from cpe_lookup.config import Settings, get_settings
from cpe_lookup.models import AP, APIExceptionModel, DeviceOnlineStatus
from cpe_lookup.modules.ap_info import get_ap_info
from cpe_lookup.modules.redis_db import RedisClient
from cpe_lookup.types import MACAddressStr

log = structlog.get_logger()
settings: Settings = get_settings()


frontiir_oui = re.compile(r"^Frontiir.*")
ruckus_oui = re.compile(r"^Ruckus.*")


rdb = RedisClient(
    redis_dsn=settings.redis_dsn,
    redis_pwd=settings.redis_pwd,
    socket_timeout=settings.redis_timeout,
)

openapi_tags = [
    {
        "name": "ap-info",
        "description": "Endpoints for retrieving Access Point information from OSS API.",
    }
]

router = APIRouter(
    prefix="",
    tags=["ap-info"],
    responses={
        404: {"model": APIExceptionModel, "description": "AP not found"},
        503: {
            "model": APIExceptionModel,
            "description": "Service or upstream unavailable temporarily",
        },
    },
)


def valid_bssid(bssid) -> str:
    try:
        return MACAddressStr(bssid)
    except ValueError:
        raise HTTPException(400, "Invalid BSSID!")


async def generate_ap_info(data, check_realtime):
    if check_realtime and data.mgmt_ip:
        data.online_status = (
            DeviceOnlineStatus.UP
            if await data.check_ping()
            else DeviceOnlineStatus.DOWN
        )
    else:
        data.online_status = (
            DeviceOnlineStatus.UP
            if await data.status_by_lastseen()
            else DeviceOnlineStatus.DOWN
        )

    if data.online_status == DeviceOnlineStatus.UP:
        data.last_seen = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    return data


@router.get(
    "/{bssid:str}/status",
    summary="Get wireless uplink AP status for both Ruckus and Frontiir AP",
    response_model=AP,
    response_description="AP device information and online status",
)
async def get_ap_status(
    request: Request,
    bssid: str = Depends(valid_bssid),
    check_realtime: bool = False,
):
    """Get AP technical information and online status."""
    try:
        cache_control = request.headers.get("cache-control") or ""
        cache_control_list = cache_control.lower().split(",")

        if "no-cache" in cache_control_list:
            ap, url, status_code = await get_ap_info(bssid)
            if not ap:
                log.msg("AP info not found!", bssid=bssid)
                raise HTTPException(404, "AP not found!")

            ap: AP = await generate_ap_info(ap, check_realtime)

            log.msg(
                "Get AP info from original and not store in cache",
                cache_control=request.headers.get("cache-control"),
                user_agent=request.headers.get("user-agent"),
                url=url,
                status_code=status_code,
                resp=ap,
            )
            return ap

        elif "max-age=0" in cache_control_list:
            rdb.del_data(f"ap_{bssid}")
            ap, url, status_code = await get_ap_info(bssid)

            if not ap:
                rdb.set_data(
                    key=f"ap_{bssid}",
                    expire=settings.cache_ap_expire,
                    value=json.dumps({}),
                )
                log.msg(
                    "Latest AP info not found and store empty json in cache.",
                    bssid=bssid,
                )
                raise HTTPException(404, f"AP info for {bssid} not found.")

            ap: AP = await generate_ap_info(ap, check_realtime)

            rdb.set_data(
                key=f"ap_{bssid}",
                expire=settings.cache_ap_expire,
                value=ap.json(),
            )

            log.msg(
                "GET latest AP info and store in cache.",
                cache_control=request.headers.get("cache-control"),
                user_agent=request.headers.get("user-agent"),
                url=url,
                status_code=status_code,
                resp=ap,
            )
            return ap

        check_ap_info = rdb.is_exist(f"ap_{bssid}")
        if check_ap_info:
            r_ap_info = rdb.get_data(f"ap_{bssid}")
            ap_info = json.loads(r_ap_info)
            if not ap_info:
                log.msg("AP info from cache value is empty.", bssid=bssid)
                raise HTTPException(404, f"AP info for {bssid} not found.")
            log.msg(
                "GET AP info from cache.",
                cache_control=request.headers.get("cache-control"),
                user_agent=request.headers.get("user-agent"),
                resp=ap_info,
            )
            return ap_info
        else:
            ap, url, status_code = await get_ap_info(bssid)

            if not ap:
                rdb.set_data(
                    key=f"ap_{bssid}",
                    expire=settings.cache_ap_expire,
                    value=json.dumps({}),
                )
                log.msg(
                    "AP info from original is not found and store empty json in cache.",
                    bssid=bssid,
                )
                raise HTTPException(404, f"AP info for {bssid} not found.")

            ap: AP = await generate_ap_info(ap, check_realtime)

            rdb.set_data(
                key=f"ap_{bssid}",
                expire=settings.cache_ap_expire,
                value=ap.json(),
            )

            log.msg(
                "GET AP info from original and store in cache.",
                cache_control=request.headers.get("cache-control"),
                user_agent=request.headers.get("user-agent"),
                url=url,
                status_code=status_code,
                resp=ap,
            )
            return ap

    except ConnectionError as e:
        log.error("Failed to connect Redis!", error=str(e))
        ap, url, status_code = await get_ap_info(bssid)

        if not ap:
            log.msg("AP info not found!", bssid=bssid)
            raise HTTPException(404, f"AP info for {bssid} not found.")

        ap: AP = await generate_ap_info(ap, check_realtime)

        log.error(
            "Redis Connection Fails. GET AP info from original.",
            cache_control=request.headers.get("cache-control"),
            user_agent=request.headers.get("user-agent"),
            url=url,
            status_code=status_code,
            resp=ap,
            error=str(e),
        )
        return ap
    except (RequestError, ReadTimeout, ConnectTimeout) as exc:
        log.msg("Wireless uplink info API request failed to upstream.", error=exc)
        raise HTTPException(
            504, detail="Wireless uplink info API request failed to upstream."
        )
    except HTTPStatusError as exc:
        raise HTTPException(exc.response.status_code, detail=exc.response.text)
    except ConnectError:
        raise HTTPException(500, "All connection attempts failed")
