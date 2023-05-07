from typing import List

import structlog
from fastapi import APIRouter, Depends, HTTPException
from httpx import AsyncClient, HTTPStatusError, RequestError
from starlette_context import context

from ..config import Settings, get_settings
from ..models import CustomerSubscriptionInfo

log = structlog.get_logger()

openapi_tags = [
    {
        "name": "customer-info",
        "description": "Endpoints for retrieving CPE ID and subscription plan status from business systems.",
    }
]

router = APIRouter(tags=["customer_subscription-info"])


@router.get(
    "/{customerid:str}/subscription",
    summary="Get cpe id and subscription status",
    response_model=List[CustomerSubscriptionInfo],
    response_description="CPE ID and subscription status",
)
async def customer_subscription_info(
    customerid: str, settings: Settings = Depends(get_settings)
):
    customer_subscription_info = []
    endpoint = settings.customer_subscription_status_endpoint.format(
        customerid=customerid
    )
    async with AsyncClient() as client:
        try:
            response = await client.get(endpoint)
            log.msg(
                "Get CPE ID and subscription plan Info",
                url=response.url,
                status_code=response.status_code,
            )
            response.raise_for_status()
            data = response.json()["customer_subscription_info"]
            subscription = data
            for s in subscription:
                c = CustomerSubscriptionInfo(customerid=customerid)
                c.cpe_id = s["cpe_id"]
                c.subscription_status = s["subscription_status"]
                c.service_type = s["service_type"]
                c.current_package = s["current_package"]
                c.billing_township = s["billing_township"]
                customer_subscription_info.append(c)
        except RequestError as exc:
            log.msg(
                "Plan Info API request failed to Data Warehouse",
                error=exc,
                **context.data,
            )
            raise HTTPException(503, detail="Plan Info API request failed to upstream")
        except HTTPStatusError as exc:
            log.msg(
                "Plan Info API response not successful",
                error=exc,
                **context.data,
            )
            raise HTTPException(exc.response.status_code, detail=exc.response.text)
    # context.update({"customer_subscription_info": customer_subscription_info})
    log.msg("subscription info retrieved", **context.data)
    return customer_subscription_info
