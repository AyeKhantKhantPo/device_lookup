import json

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from redis.exceptions import ConnectionError
from starlette_context import context

from ..config import Settings, get_settings
from ..modules.redis_db import RedisClient
from ..modules.rt_info import get_asset_info, get_tkt_info

log = structlog.get_logger()
settings: Settings = get_settings()


rdb = RedisClient(
    redis_dsn=settings.redis_dsn,
    redis_pwd=settings.redis_pwd,
    socket_timeout=settings.redis_timeout,
)


openapi_tags = [
    {
        "name": "ticket-info",
        "description": "Endpoints for retrieving ticket informations and asset informations from Request Tracker(RT).",
    }
]

router = APIRouter(tags=["ticket-info"])


async def process_tkt_info(cid: str) -> json:
    resp = await get_tkt_info(cid)
    tkt_info = resp.json()
    context.update(tkt_info)
    return tkt_info, resp.url, resp.status_code


async def process_asset_info(cid: str) -> json:
    resp = await get_asset_info(cid)
    asset_info = resp.json()
    context.update(asset_info)
    return asset_info, resp.url, resp.status_code


@router.get(
    "/{cid:str}/tktinfo",
    summary="Get TKT info of CPE",
    response_description="Ticket informations associated with the CPE",
)
async def ticketinfo(cid, request: Request, settings: Settings = Depends(get_settings)):
    try:
        tkt_info = None
        cache_control = request.headers.get("cache-control") or ""
        cache_control_list = cache_control.lower().split(",")
        if "no-cache" in cache_control_list:
            tkt_info, url, status_code = await process_tkt_info(cid)
            if tkt_info:
                log.msg(
                    "Get TKT info from original and not store in cache",
                    cache_control=request.headers.get("cache-control"),
                    user_agent=request.headers.get("user-agent"),
                    url=url,
                    status_code=status_code,
                    resp=tkt_info,
                )
                return tkt_info
            else:
                log.msg("TKT info not found!", cid=cid)
                raise HTTPException(404, "TKT info not found!")
        elif "max-age=0" in cache_control_list:
            rdb.del_data(f"tkt_{cid}")
            tkt_info, url, status_code = await process_tkt_info(cid)
            rdb.set_data(
                key=f"tkt_{cid}",
                expire=settings.cache_tkt_expire,
                value=json.dumps(tkt_info),
            )
            if tkt_info:
                log.msg(
                    "GET latest TKT info and store in cache.",
                    cache_control=request.headers.get("cache-control"),
                    user_agent=request.headers.get("user-agent"),
                    url=url,
                    status_code=status_code,
                    resp=tkt_info,
                )
                return tkt_info
            else:
                log.msg("TKT info not found!", cid=cid)
                raise HTTPException(404, "TKT info not found!")

        r_tkt_info = rdb.get_data(f"tkt_{cid}")
        if r_tkt_info:
            tkt_info = json.loads(r_tkt_info)
            log.msg(
                "GET TKT info from cache.",
                cache_control=request.headers.get("cache-control"),
                user_agent=request.headers.get("user-agent"),
                cid=cid,
                resp=tkt_info,
            )
            return tkt_info
        else:
            tkt_info, url, status_code = await process_tkt_info(cid)
            rdb.set_data(
                key=f"tkt_{cid}",
                expire=settings.cache_tkt_expire,
                value=json.dumps(tkt_info),
            )
            if tkt_info:
                log.msg(
                    "GET TKT info from original and store in cache.",
                    cache_control=request.headers.get("cache-control"),
                    user_agent=request.headers.get("user-agent"),
                    url=url,
                    status_code=status_code,
                    resp=tkt_info,
                )
                return tkt_info
            else:
                log.msg("TKT info not found!", cid=cid)
                raise HTTPException(404, "TKT info not found!")

    except ConnectionError as e:
        log.error("Failed to connect Redis!", error=str(e))
        tkt_info, url, status_code = await process_tkt_info(cid)

        if tkt_info:
            log.msg(
                "Redis Connection Fails!!! GET TKT info from original.",
                cache_control=request.headers.get("cache-control"),
                user_agent=request.headers.get("user-agent"),
                url=url,
                status_code=status_code,
                resp=tkt_info,
                error=str(e),
            )
            return tkt_info
        else:
            log.msg("TKT info not found!", cid=cid)
            raise HTTPException(404, "TKT info not found!")
    # except Exception as e:
    #     log.msg("Raise Exception in GET TKT info.", error=str(e))
    #     raise HTTPException(500, "Raise Exception in GET TKT info.")


@router.get(
    "/{cid:str}/assetinfo",
    summary="Get asset info of CPE",
    response_description="Asset informations associated with the CPE",
)
async def assetinfo(cid, request: Request, settings: Settings = Depends(get_settings)):
    try:
        asset_info = None
        cache_control = request.headers.get("cache-control") or ""
        cache_control_list = cache_control.lower().split(",")
        if "no-cache" in cache_control_list:
            asset_info, url, status_code = await process_asset_info(cid)
            if asset_info:
                log.msg(
                    "Get Asset info from original and not store in cache.",
                    cache_control=request.headers.get("cache-control"),
                    user_agent=request.headers.get("user-agent"),
                    url=url,
                    status_code=status_code,
                    resp=asset_info,
                )
                return asset_info
            else:
                log.msg("Asset info not found!", cid=cid)
                raise HTTPException(404, "Asset info not found!")

        elif "max-age=0" in cache_control_list:
            rdb.del_data(f"asset_{cid}")
            asset_info, url, status_code = await process_asset_info(cid)
            rdb.set_data(
                key=f"asset_{cid}",
                expire=settings.cache_asset_expire,
                value=json.dumps(asset_info),
            )

            if asset_info:
                log.msg(
                    "GET latest asset info and store in cache.",
                    cache_control=request.headers.get("cache-control"),
                    user_agent=request.headers.get("user-agent"),
                    url=url,
                    status_code=status_code,
                    resp=asset_info,
                )
                return asset_info
            else:
                log.msg("Asset info not found!", cid=cid)
                raise HTTPException(404, "Asset info not found!")

        r_asset_info = rdb.get_data(f"asset_{cid}")
        if r_asset_info:
            asset_info = json.loads(r_asset_info)
            log.msg(
                "GET Asset info from cache.",
                cache_control=request.headers.get("cache-control"),
                user_agent=request.headers.get("user-agent"),
                cid=cid,
                resp=asset_info,
            )
            return asset_info
        else:
            asset_info, url, status_code = await process_asset_info(cid)
            rdb.set_data(
                key=f"asset_{cid}",
                expire=settings.cache_asset_expire,
                value=json.dumps(asset_info),
            )
            if asset_info:
                log.msg(
                    "GET Asset info from original and store in cache.",
                    cache_control=request.headers.get("cache-control"),
                    user_agent=request.headers.get("user-agent"),
                    url=url,
                    status_code=status_code,
                    resp=asset_info,
                )
                return asset_info
            else:
                log.msg("Asset info not found!", cid=cid)
                raise HTTPException(404, "Asset info not found!")

    except ConnectionError as e:
        log.error("Failed to connect Redis!", error=str(e))
        asset_info, url, status_code = await process_asset_info(cid)

        if asset_info:
            log.msg(
                "Redis Connection Fails!!! GET Asset info from original.",
                cache_control=request.headers.get("cache-control"),
                user_agent=request.headers.get("user-agent"),
                url=url,
                status_code=status_code,
                resp=asset_info,
                error=str(e),
            )
            return asset_info
        else:
            log.msg("Asset info not found!", cid=cid)
            raise HTTPException(404, "Asset info not found!")

    # except Exception as e:
    #     log.msg("Raise Exception in GET Asset info.", error=str(e))
    #     raise HTTPException(500, "Raise Exception in GET Asset info.")
