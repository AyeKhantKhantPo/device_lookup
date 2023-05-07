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
from cpe_lookup.models import SubscriptionInfo

log = structlog.get_logger()
settings: Settings = get_settings()


async def get_cpe_subscription(cid: str):
    cpe_subscription = SubscriptionInfo(cid=cid)
    async with AsyncClient(timeout=get_settings().api_timeout) as client:
        try:
            response = await client.post(
                settings.cpe_plan_info_endpoint, json={"cpeid": cid}
            )
            log.msg(
                "Get CPE installation type and plan Info",
                url=response.url,
                status_code=response.status_code,
            )
            response.raise_for_status()

            data = response.json()["cpe_installation_plan_info"]
            cpe_subscription.subscribed_plan = data["plan"]
            cpe_subscription.installation_type = data["installation_type"]
            cpe_subscription.subscription_status = data["subscription_status"]
            cpe_subscription.service_type = data["service_type"]

        except (RequestError, ReadTimeout, ConnectTimeout) as exc:
            log.msg(
                "Plan info API request failed to Data Warehouse.",
                error=exc,
                **context.data,
            )
            raise HTTPException(
                504, detail="Plan info API request failed to Data Warehouse."
            )
        except HTTPStatusError as exc:
            log.msg(
                "Plan Info API response not successful",
                error=exc,
                **context.data,
            )
            if exc.response.status_code == 404:
                return None, response.url, response.status_code
            else:
                raise HTTPException(exc.response.status_code, detail=exc.response.text)
    context.update(cpe_subscription)
    log.msg("subscription info retrieved", **context.data)
    return cpe_subscription, response.url, response.status_code
