from functools import lru_cache

from pydantic import AnyUrl, BaseSettings, HttpUrl


class Settings(BaseSettings):
    app_root_path: str = ""
    internal_routes_prefix: str = ""
    cpe_plan_info_endpoint: HttpUrl = "http://127.0.0.1:9000/bss/v1/cpe_plan_info.php"
    customer_subscription_status_endpoint: HttpUrl = "http://127.0.0.1:9000/bss/v1/customer_subscription_status.php?customer_id={customerid}"
    cpe_status_endpoint: HttpUrl = "http://127.0.0.1:9000//api/v1/cpes/deviceinfo"
    ap_info_endpoint: HttpUrl = (
        "http://127.0.0.1:8001/devices/aps?bssid_for_cpe={bssid}"
    )
    device_up_duration: int = 15
    fiber_feature_enabled: bool = True
    fiber_route: str = "/uplink/fiber/"
    fiber_uplink_endpoint: HttpUrl = "http://127.0.0.1:8000/api/onu/{cid}/"
    fiber_auth_key: str = "Bearer 8eafdadfkalfdalfdafdnads24345jnfafd"
    fiber_auth_user: str = "cpe_lookup"
    api_timeout: int = 10
    redis_dsn: AnyUrl = "redis://localhost:6379"
    redis_pwd: str = "dfafdadfqefvfv"
    redis_timeout: int = 10
    rt_feature_enabled: bool = True
    rt_route: str = "/tickets/cpe/"
    rt_token: str = "1-3419afnasfdkafdlaf"
    rt_tkt_endpoint: HttpUrl = "http://127.0.0.1/REST/2.0/tickets?token={token}&fields=cpelookup,Status,Queue&fields[Queue]=Name&query=(%27Status%27=%27__Active__%27AND%27CF.{{CPE%20ID}}%27=%27{cid}%27)"
    rt_asset_endpoint: HttpUrl = "http://127.0.0.1/REST/2.0/assets?token={token}&query=[{{%22field%22:%22Catalog%22,%22operator%22:%22=%22,%22value%22:%223%22}},%20{{%22field%22:%22Description%22,%22operator%22:%22LIKE%22,%22value%22:%22Plan%20Status:%20Active%22,%22entry_aggregator%22:%20%22AND%22}},{{%22field%22:%22Description%22,%22operator%22:%22LIKE%22,%22entry_aggregator%22:%20%22AND%22,%22value%22:%22{cid}%22}}]"

    cache_cpe_expire: int = 3600
    cache_ap_expire: int = 3600
    cache_fiber_expire: int = 3600
    cache_subscription_expire: int = 3600
    cache_tkt_expire: int = 3600
    cache_asset_expire: int = 3600

    cid_pattern: str = "^[a-zA-Z]{2,3}[0-9]{6}$"

    class Config:
        env_file = ".env"


@lru_cache
def get_settings() -> Settings:
    return Settings()
