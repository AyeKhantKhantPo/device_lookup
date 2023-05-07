import json
import re
from datetime import datetime

import structlog
from fastapi import APIRouter, HTTPException, Request
from httpx import ConnectTimeout, HTTPStatusError, ReadTimeout, RequestError
from redis.exceptions import ConnectionError
from starlette_context import context

from cpe_lookup.config import Settings, get_settings
from cpe_lookup.models import APIExceptionModel, CPEStatus, DeviceOnlineStatus
from cpe_lookup.modules import cpems
from cpe_lookup.modules.redis_db import RedisClient

log = structlog.get_logger()
settings: Settings = get_settings()

cpe_oui = re.compile(settings.cid_pattern)

rdb = RedisClient(
    redis_dsn=settings.redis_dsn,
    redis_pwd=settings.redis_pwd,
    socket_timeout=settings.redis_timeout,
)


openapi_tags = [
    {
        "name": "cpe-info",
        "description": "Endpoints for retrieving CPE device information from CPEMS",
    }
]

router = APIRouter(prefix="", tags=["cpe-info"])


async def generate_cpe_status_info(cid, check_realtime):
    cpe_status: CPEStatus = CPEStatus()
    try:
        cpe, url, status_code = await cpems.get_cpe(cid)
        if not cpe:
            log.msg(f"{cid} not found in CPEMS", **context.data)
            return None, url, status_code

        if check_realtime and cpe.mgmt_ip:
            cpe.online_status = (
                DeviceOnlineStatus.UP
                if await cpe.check_ping()
                else DeviceOnlineStatus.DOWN
            )

        if cpe.online_status == DeviceOnlineStatus.UP:
            cpe.last_seen = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

        if cpe.category in ["CPE-E", "CPE-W", "CPE-M"]:
            cpe_status.indoor_cpe = cpe
        else:
            cpe_status.outdoor_cpe = cpe

        if cpe.category in ["CPE-O", "CPE-W"]:
            cpe_status.uplink_bssid = cpe.uplink_mac

        if cpe.uplink_cid:
            uplink_cid = cpe.uplink_cid.upper()
            uplink_cpe, url, status_code = await cpems.get_cpe(uplink_cid)

            if not uplink_cpe:
                log.msg(f"{uplink_cid} not found in CPEMS", **context.data)
                raise HTTPException(404, detail=f"CPE not found for {uplink_cid}")

            if check_realtime and uplink_cpe.mgmt_ip:
                uplink_cpe.online_status = (
                    DeviceOnlineStatus.UP
                    if await uplink_cpe.check_ping()
                    else DeviceOnlineStatus.DOWN
                )

            if uplink_cpe.online_status == DeviceOnlineStatus.UP:
                uplink_cpe.last_seen = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

            cpe_status.outdoor_cpe = uplink_cpe
            cpe_status.uplink_bssid = uplink_cpe.uplink_mac

    except (RequestError, HTTPStatusError) as exc:
        log.msg("CPE Status API failed to CPEMS", error=exc, **context.data)
        raise HTTPException(503, detail="Error getting CPE status from CPEMS")

    return cpe_status, url, status_code


@router.get(
    "/{cid}/status",
    summary="Get device status for both indoor and outdoor CPEs",
    response_model=CPEStatus,
    response_description="CPE device information and online status",
    responses={
        404: {"model": APIExceptionModel, "description": "CPE not found"},
        503: {
            "model": APIExceptionModel,
            "description": "Service or upstream unavailable temporarily",
        },
    },
)
async def get_cpe_status(request: Request, cid: str, check_realtime: bool = False):
    """Get CPE technical information and online status."""
    try:
        cid: str = cid.upper()
        if not cpe_oui.search(cid):
            log.msg(f"{cid} is invalid CID format.")
            raise HTTPException(422, detail=f"{cid} is invalid CID format.")

        cache_control = request.headers.get("cache-control") or ""
        cache_control_list = cache_control.lower().split(",")

        if "no-cache" in cache_control_list:
            cpe_status, url, status_code = await generate_cpe_status_info(
                cid, check_realtime
            )
            if not cpe_status:
                log.msg("CPE info not found!", cid=cid)
                raise HTTPException(404, f"CPE not found for {cid}.")

            log.msg(
                "Get CPE info from original and not store in cache",
                cache_control=request.headers.get("cache-control"),
                user_agent=request.headers.get("user-agent"),
                url=url,
                status_code=status_code,
                resp=cpe_status,
            )
            return cpe_status

        elif "max-age=0" in cache_control_list:
            rdb.del_data(f"cpe_{cid}")
            cpe_status, url, status_code = await generate_cpe_status_info(
                cid, check_realtime
            )

            if not cpe_status:
                rdb.set_data(
                    key=f"cpe_{cid}",
                    expire=settings.cache_cpe_expire,
                    value=json.dumps({}),
                )
                log.msg(
                    "Latest CPE info not found and store empty json in cache.", cid=cid
                )
                raise HTTPException(404, f"CPE info not found for {cid}")

            rdb.set_data(
                key=f"cpe_{cid}",
                expire=settings.cache_cpe_expire,
                value=cpe_status.json(),
            )

            log.msg(
                "GET latest CPE info and store in cache.",
                cache_control=request.headers.get("cache-control"),
                user_agent=request.headers.get("user-agent"),
                url=url,
                status_code=status_code,
                resp=cpe_status,
            )
            return cpe_status

        check_cpe_info = rdb.is_exist(f"cpe_{cid}")
        if check_cpe_info:
            r_cpe_info = rdb.get_data(f"cpe_{cid}")
            cpe_status = json.loads(r_cpe_info)

            if not cpe_status:
                log.msg("CPE info from cache value is empty.", cid=cid)
                raise HTTPException(404, f"CPE info not found for {cid}.")

            log.msg(
                "GET CPE info from cache.",
                cache_control=request.headers.get("cache-control"),
                user_agent=request.headers.get("user-agent"),
                resp=cpe_status,
            )
            return cpe_status
        else:
            cpe_status, url, status_code = await generate_cpe_status_info(
                cid, check_realtime
            )

            if not cpe_status:
                rdb.set_data(
                    key=f"cpe_{cid}",
                    expire=settings.cache_cpe_expire,
                    value=json.dumps({}),
                )
                log.msg(
                    "GET CPE info from original is not found and store empty json in cache.",
                    cid=cid,
                )
                raise HTTPException(404, f"CPE info not found for {cid}.")

            rdb.set_data(
                key=f"cpe_{cid}",
                expire=settings.cache_cpe_expire,
                value=cpe_status.json(),
            )

            log.msg(
                "GET CPE_status info from original and store in cache.",
                cache_control=request.headers.get("cache-control"),
                user_agent=request.headers.get("user-agent"),
                url=url,
                status_code=status_code,
                resp=cpe_status,
            )
            return cpe_status

    except ConnectionError as e:
        log.error("Failed to connect Redis!", error=str(e))
        cpe_status, url, status_code = await generate_cpe_status_info(
            cid, check_realtime
        )

        if not cpe_status:
            log.msg("CPE_status info not found!", cid=cid)
            raise HTTPException(404, f"CPE_status info not found for {cid}")

        log.error(
            "Redis Connection Fails. GET CPE_status info from original.",
            cache_control=request.headers.get("cache-control"),
            user_agent=request.headers.get("user-agent"),
            url=url,
            status_code=status_code,
            resp=cpe_status,
            error=str(e),
        )
        return cpe_status

    except (RequestError, ReadTimeout, ConnectTimeout) as exc:
        log.msg(
            "CPE info API request failed to upstream.",
            error=exc,
        )
        raise HTTPException(504, detail="CPE info API request failed to upstream.")
    except HTTPStatusError as exc:
        raise HTTPException(exc.response.status_code, detail=exc.response.text)
