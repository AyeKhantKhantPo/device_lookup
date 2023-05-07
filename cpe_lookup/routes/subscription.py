import json
import re

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from redis.exceptions import ConnectionError

from cpe_lookup.config import Settings, get_settings
from cpe_lookup.models import SubscriptionInfo
from cpe_lookup.modules.data_warehouse import get_cpe_subscription
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
        "name": "subscription-info",
        "description": "Endpoints for retrieving CPE subscription and service information from business systems.",
    }
]

router = APIRouter(tags=["subscription-info"])


@router.get(
    "/{cid:str}/subscriptions/internet",
    summary="Get CPE Plan and Installation Type",
    response_model=SubscriptionInfo,
    response_description="Service subscription associated with the CPE and type of installation provided.",
)
async def cpe_subscription(
    request: Request, cid: str, settings: Settings = Depends(get_settings)
):
    try:
        cid: str = cid.upper()
        if not cpe_oui.search(cid):
            log.msg(f"{cid} is invalid CID format.")
            raise HTTPException(422, detail=f"{cid} is invalid CID format.")

        cache_control = request.headers.get("cache-control") or ""
        cache_control_list = cache_control.lower().split(",")

        if "no-cache" in cache_control_list:
            cpe_subscription, url, status_code = await get_cpe_subscription(cid)
            if not cpe_subscription:
                log.msg("CPE subscription info not found!", cid=cid)
                raise HTTPException(404, f"CPE subscription of {cid} not found.")

            log.msg(
                "Get CPE subscription info from original and not store in cache",
                cache_control=request.headers.get("cache-control"),
                user_agent=request.headers.get("user-agent"),
                url=url,
                status_code=status_code,
                resp=cpe_subscription,
            )
            return cpe_subscription

        elif "max-age=0" in cache_control_list:
            rdb.del_data(f"subscription_{cid}")
            cpe_subscription, url, status_code = await get_cpe_subscription(cid)

            if not cpe_subscription:
                rdb.set_data(
                    key=f"subscription_{cid}",
                    expire=settings.cache_subscription_expire,
                    value=json.dumps({}),
                )
                log.msg(
                    "Latest CPE subscription info is not found and store empty json in cache.",
                    cid=cid,
                )
                raise HTTPException(404, f"CPE subscription info of {cid} not found!")

            rdb.set_data(
                key=f"subscription_{cid}",
                expire=settings.cache_subscription_expire,
                value=cpe_subscription.json(),
            )

            log.msg(
                "GET latest cpe_subscription info and store in cache.",
                cache_control=request.headers.get("cache-control"),
                user_agent=request.headers.get("user-agent"),
                url=url,
                status_code=status_code,
                resp=cpe_subscription,
            )
            return cpe_subscription

        check_subscription = rdb.is_exist(f"subscription_{cid}")
        if check_subscription:
            r_subscription = rdb.get_data(f"subscription_{cid}")
            cpe_subscription = json.loads(r_subscription)

            if not cpe_subscription:
                log.msg("Subscription info from cache value is empty.", cid=cid)
                raise HTTPException(404, f"CPE subscription info of {cid} not found!")

            log.msg(
                "GET CPE subscription info from cache.",
                cache_control=request.headers.get("cache-control"),
                user_agent=request.headers.get("user-agent"),
                resp=cpe_subscription,
            )
            return cpe_subscription
        else:
            cpe_subscription, url, status_code = await get_cpe_subscription(cid)

            if not cpe_subscription:
                rdb.set_data(
                    key=f"subscription_{cid}",
                    expire=settings.cache_subscription_expire,
                    value=json.dumps({}),
                )
                log.msg(
                    "CPE subscription info is not found and store empty json in cache.",
                    cid=cid,
                )
                raise HTTPException(404, f"CPE subscription info of {cid} not found!")

            rdb.set_data(
                key=f"subscription_{cid}",
                expire=settings.cache_subscription_expire,
                value=cpe_subscription.json(),
            )

            log.msg(
                "GET CPE subscription info from original and store in cache.",
                cache_control=request.headers.get("cache-control"),
                user_agent=request.headers.get("user-agent"),
                url=url,
                status_code=status_code,
                resp=cpe_subscription,
            )
            return cpe_subscription

    except ConnectionError as e:
        log.error("Failed to connect Redis!", error=str(e))
        cpe_subscription, url, status_code = await get_cpe_subscription(cid)

        if not cpe_subscription:
            log.msg("CPE subscription info not found!", cid=cid)
            raise HTTPException(404, f"CPE subscription info of {cid} not found.")

        log.error(
            "Redis Connection Fails. GET cpe_subscription info from original.",
            cache_control=request.headers.get("cache-control"),
            user_agent=request.headers.get("user-agent"),
            url=url,
            status_code=status_code,
            resp=cpe_subscription,
            error=str(e),
        )
    return cpe_subscription
