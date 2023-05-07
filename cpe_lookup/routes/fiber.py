import json
import re

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from httpx import ConnectTimeout, HTTPStatusError, ReadTimeout, RequestError
from redis.exceptions import ConnectionError

from cpe_lookup.config import Settings, get_settings
from cpe_lookup.models import FiberInfo
from cpe_lookup.modules.oltms import get_fiber_uplink
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
        "name": "fiber-uplink-info",
        "description": "Endpoints for retrieving fiber uplink information and status.",
    }
]

router = APIRouter(tags=["fiber-uplink-info"])


@router.get(
    "/{cid:str}/status",
    summary="Get fiber uplink info",
    response_model=FiberInfo,
    response_description="Uplink ONU and OLT informations associated with the CPE are provided.",
)
async def fiber_uplink(
    request: Request, cid: str, settings: Settings = Depends(get_settings)
):
    """Get Fiber uplink information and online status."""
    try:
        cid: str = cid.upper()
        if not cpe_oui.search(cid):
            log.msg(f"{cid} is invalid CID format.")
            raise HTTPException(422, detail=f"{cid} is invalid CID format.")
        cache_control = request.headers.get("cache-control") or ""
        cache_control_list = cache_control.lower().split(",")

        if "no-cache" in cache_control_list:
            fiber, url, status_code = await get_fiber_uplink(cid)
            if not fiber:
                log.msg("Uplink fiber info not found!", cid=cid)
                raise HTTPException(404, f"Uplink fiber for {cid} not found!")

            log.msg(
                "Get uplink fiber info from original and not store in cache",
                cache_control=request.headers.get("cache-control"),
                user_agent=request.headers.get("user-agent"),
                url=url,
                status_code=status_code,
                resp=fiber,
            )
            return fiber

        elif "max-age=0" in cache_control_list:
            rdb.del_data(f"fiber_{cid}")
            fiber, url, status_code = await get_fiber_uplink(cid)

            if not fiber:
                rdb.set_data(
                    key=f"fiber_{cid}",
                    expire=settings.cache_fiber_expire,
                    value=json.dumps({}),
                )

                log.msg(
                    "Latest Uplink fiber info not found and store empty json in cache.",
                    cid=cid,
                )
                raise HTTPException(404, f"Uplink fiber info for {cid} not found.")

            rdb.set_data(
                key=f"fiber_{cid}",
                expire=settings.cache_fiber_expire,
                value=fiber.json(),
            )

            log.msg(
                "GET latest uplink fiber info and store in cache.",
                cache_control=request.headers.get("cache-control"),
                user_agent=request.headers.get("user-agent"),
                url=url,
                status_code=status_code,
                resp=fiber,
            )
            return fiber

        check_fiber_info = rdb.is_exist(f"fiber_{cid}")
        if check_fiber_info:
            r_fiber_info = rdb.get_data(f"fiber_{cid}")
            fiber_info = json.loads(r_fiber_info)

            if not fiber_info:
                log.msg("Uplink fiber info from cache value is empty.", cid=cid)
                raise HTTPException(404, f"Uplink fiber info for {cid} not found.")

            log.msg(
                "GET uplink fiber info from cache.",
                cache_control=request.headers.get("cache-control"),
                user_agent=request.headers.get("user-agent"),
                resp=fiber_info,
            )
            return fiber_info
        else:
            fiber, url, status_code = await get_fiber_uplink(cid)

            if not fiber:
                rdb.set_data(
                    key=f"fiber_{cid}",
                    expire=settings.cache_fiber_expire,
                    value=json.dumps({}),
                )

                log.msg(
                    "Uplink fiber info from original not found and store empty json in cache.",
                    cid=cid,
                )
                raise HTTPException(404, f"Uplink fiber info for {cid} not found.")

            rdb.set_data(
                key=f"fiber_{cid}",
                expire=settings.cache_fiber_expire,
                value=fiber.json(),
            )

            log.msg(
                "GET fiber info from original and store in cache.",
                cache_control=request.headers.get("cache-control"),
                user_agent=request.headers.get("user-agent"),
                url=url,
                status_code=status_code,
                resp=fiber,
            )
            return fiber

    except ConnectionError as e:
        log.error("Failed to connect Redis!", error=str(e))
        fiber, url, status_code = await get_fiber_uplink(cid)

        if not fiber:
            log.msg("Uplink fiber info not found!", cid=cid)
            raise HTTPException(404, "Uplink fiber info not found!")

        log.error(
            "Redis Connection Fails. GET fiber info from original.",
            cache_control=request.headers.get("cache-control"),
            user_agent=request.headers.get("user-agent"),
            url=url,
            status_code=status_code,
            resp=fiber,
            error=str(e),
        )
        return fiber

    except (RequestError, ReadTimeout, ConnectTimeout) as exc:
        log.msg(
            "Fiber uplink info API request failed to OLTMS",
            error=exc,
        )
        raise HTTPException(
            504, detail="Fiber uplink info API request failed to upstream"
        )
    except HTTPStatusError as exc:
        log.msg(
            "Fiber uplink info API response not successful",
            error=exc,
        )
        raise HTTPException(exc.response.status_code, detail=exc.response.text)
