from __future__ import annotations

import time
from datetime import datetime, timedelta
from enum import Enum, unique
from ipaddress import IPv4Address, IPv4Interface
from typing import Dict, Optional, Union

import structlog
from netaddr import IPNetwork
from pydantic import BaseModel as PydanticBaseModel
from pydantic import Field, validator

from .config import get_settings
from .modules import netops
from .types import MACAddressStr

log = structlog.get_logger()


class APIExceptionModel(PydanticBaseModel):
    detail: str


@unique
class DeviceOnlineStatus(str, Enum):
    UP = "up"
    DOWN = "down"
    UNKNOWN = "unknown"


@unique
class CPECategory(str, Enum):
    MOBILE = "CPE-M"
    ETHERNET = "CPE-E"
    OUTDOOR = "CPE-O"
    WIRELESS = "CPE-W"


# class MACAddress(str):
#     @classmethod
#     def __get_validators__(cls):
#         yield cls.validate

#     @classmethod
#     def validate(cls, v):
#         if not valid_mac(v):
#             raise TypeError("must be valid EUI48 MAC address")
#         return cls(str(EUI(v)))


class BaseModel(PydanticBaseModel):
    class Config:
        arbitrary_types_allowed = True
        use_enum_values = True
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            IPv4Address: lambda v: str(v),
        }


class SubscriptionInfo(BaseModel):
    cid: str = Field(title="CPE ID")
    subscribed_plan: Optional[str] = Field(default="na")
    installation_type: Optional[str] = Field(default="na")
    subscription_status: Optional[str] = Field(default="na")
    service_type: Optional[str] = Field(default="na")


class CustomerSubscriptionInfo(BaseModel):
    customerid: str = Field(title="Customer ID")
    customer_id: Optional[str] = Field(default="na")
    cpe_id: Optional[str] = Field(default="na")
    subscription_status: Optional[str] = Field(default="na")
    service_type: Optional[str] = Field(default="na")
    current_package: Optional[str] = Field(default="na")
    billing_township: Optional[str] = Field(default="na")


class CPEDeviceInfo(BaseModel):
    cid: str = Field(title="CPE ID")
    mac: MACAddressStr = Field(title="MAC Address")
    serial: str = Field(title="Serial Number")
    model: str = Field(title="Device Model")
    category: CPECategory = Field(title="Uplink Type")
    data_ipaddr: Optional[str] = Field(title="Data Plane IP Address")
    mgmt_ipaddr: Optional[str] = Field(title="Control Plane IP Address")
    uplink_cid: Optional[str] = Field(title="Uplink Device ID")
    uplink_mac: Optional[str] = Field(title="Uplink Device MAC Address")
    last_seen: str = Field(title="Last Seen")


class IfaceAddress(BaseModel):
    ip: Optional[IPv4Address] = Field(title="IPv4 Address")
    netmask: Optional[IPv4Address] = Field(title="IPv4 Netmask")
    cidr: Optional[IPv4Interface] = Field(title="IPv4 CIDR Address")

    @classmethod
    def FromCIDR(cls, ip_cidr: str) -> IfaceAddress:
        try:
            ipnet = IPNetwork(ip_cidr)
            return cls(ip=str(ipnet.ip), netmask=str(ipnet.netmask), cidr=ip_cidr)
        except TypeError:
            return cls(ip="", netmask="", cidr=ip_cidr)


class NetworkDevice(BaseModel):
    mac: str = Field(title="MAC Address")
    serial: Optional[str] = Field(title="Serial Number")
    model: Optional[str] = Field(title="Model")
    interfaces: Optional[Dict[str, IfaceAddress]] = Field(default=dict())

    @validator("mac")
    def validate_mac(cls, v) -> Optional[str]:
        return MACAddressStr(v)

    @property
    def mgmt_ip(self) -> Union[str, None]:
        ip = None
        mgmt = self.interfaces.get("mgmt")
        if mgmt:
            ip = str(mgmt.ip)
        return ip

    def add_interface(self, iface_name: str, iface_address: IfaceAddress) -> None:
        self.interfaces[iface_name] = iface_address

    def remove_interface(self, iface_name: str) -> None:
        try:
            _ = self.interfaces.pop(iface_name)
        except KeyError:
            raise

    async def check_ping(self):
        return await netops.ping_to_ip(self.mgmt_ip)

    async def status_by_lastseen(self):
        last_timelimit = datetime.now() - timedelta(
            minutes=get_settings().device_up_duration
        )
        if self.last_seen > last_timelimit:
            return True
        return False


class CPE(NetworkDevice):
    cid: str = Field(title="CPE ID")
    category: CPECategory = Field(title="CPE Category")
    last_seen: Optional[datetime] = Field(title="Last Seen Timestamp")
    uplink_cid: Optional[str] = Field(title="Uplink CPE ID")
    uplink_mac: Optional[str] = Field(title="Uplink MAC Address")
    online_status: Optional[DeviceOnlineStatus] = Field(
        title="Online Status", default=DeviceOnlineStatus.UNKNOWN
    )

    @validator("*", pre=True)
    def empty_str_to_none(cls, v) -> Optional[str]:
        if v == "":
            return None
        return v

    @validator("uplink_cid")
    def validate_cid(cls, v) -> Optional[str]:
        if v is None:
            return v
        return v.upper()

    @validator("uplink_mac")
    def validate_mac(cls, v) -> Optional[str]:
        if v is None:
            return v

        return MACAddressStr(v)

    @classmethod
    def FromDeviceInfo(cls, device_info: CPEDeviceInfo):
        if device_info.uplink_cid:
            uplink_cid = device_info.uplink_cid.upper()
        else:
            uplink_cid = None

        obj = cls(
            cid=device_info.cid.upper(),
            mac=device_info.mac,
            serial=device_info.serial,
            model=device_info.model,
            category=device_info.category,
            last_seen=datetime.fromisoformat(device_info.last_seen),
            uplink_cid=uplink_cid,
            uplink_mac=device_info.uplink_mac,
        )

        obj.add_interface("mgmt", "")
        obj.add_interface("data", "")
        if device_info.mgmt_ipaddr:
            obj.add_interface("mgmt", IfaceAddress.FromCIDR(device_info.mgmt_ipaddr))
        if device_info.data_ipaddr:
            obj.add_interface("data", IfaceAddress.FromCIDR(device_info.data_ipaddr))
        return obj


class CPEStatus(BaseModel):
    indoor_cpe: Optional[CPE] = Field(title="Indoor CPE")
    outdoor_cpe: Optional[CPE] = Field(title="Outdoor CPE")
    uplink_bssid: Optional[str] = Field(title="Uplink BSSID", default=None)


class APDeviceInfo(BaseModel):
    cid: Optional[str] = Field(title="CPE ID")
    mac: MACAddressStr = Field(title="MAC Address")
    bssid_for_cpe: Optional[str] = Field(title="bssid for cpe")
    mgmt_ip: Optional[str] = Field(title="Control Plane IP Address")
    fw_version: Optional[str] = Field(title="Device Firmware version")
    client_script: Optional[str] = Field(title="Device Client Script version")
    model: Optional[str] = Field(title="Device Model")
    serial: Optional[str] = Field(title="Serial Number")
    name: Optional[str] = Field(title="Device Name")
    zone_name: Optional[str] = Field(title="Zone Name")
    powersave_status: Optional[Union[bool, None]] = Field(title="Powersave Status")
    uptime: Optional[float] = Field(title="Device Uptime")
    last_seen: Optional[datetime] = Field(title="Last Seen")
    updated_timestamp: Optional[datetime] = Field(title="Updated timestamp")


class AP(NetworkDevice):
    cid: Optional[str] = Field(title="CPE ID")
    fw_version: Optional[str] = Field(title="Firmware version")
    client_script: Optional[str] = Field(title="Client script version")
    name: Optional[str] = Field(title="Device Name")
    zone_name: Optional[str] = Field(title="Zone Name")
    powersave_status: Optional[Union[bool, None]] = Field(title="Powersave Status")
    uptime: Optional[float] = Field(title="Device uptime")
    last_seen: Optional[datetime] = Field(title="Last Seen Timestamp")
    updated_timestamp: Optional[datetime] = Field(title="Updated Timestamp")
    online_status: Optional[DeviceOnlineStatus] = Field(
        title="Online Status", default=DeviceOnlineStatus.UNKNOWN
    )

    @validator("*", pre=True)
    def empty_str_to_none(cls, v) -> Optional[str]:
        if v == "":
            return None
        return v

    @classmethod
    def utc_to_local(cls, utc_datetime):
        now_timestamp = time.time()
        offset = datetime.fromtimestamp(now_timestamp) - datetime.utcfromtimestamp(
            now_timestamp
        )
        local_datetime = utc_datetime + offset
        return local_datetime.strftime("%Y-%m-%dT%H:%M:%S")

    @classmethod
    def FromDeviceInfo(cls, device_info: APDeviceInfo):
        cid = None
        if device_info.cid:
            cid = device_info.cid.upper()

        local_time = None
        if device_info.last_seen:
            local_time = cls.utc_to_local(device_info.last_seen)

        obj = cls(
            cid=cid,
            mac=device_info.mac,
            bssid_for_cpe=device_info.bssid_for_cpe,
            name=device_info.name,
            zone_name=device_info.zone_name,
            powersave_status=device_info.powersave_status,
            serial=device_info.serial,
            model=device_info.model,
            fw_version=device_info.fw_version,
            client_script=device_info.client_script,
            uptime=device_info.uptime,
            last_seen=local_time,
            updated_timestamp=device_info.updated_timestamp.strftime(
                "%Y-%m-%dT%H:%M:%S"
            ),
        )
        obj.add_interface("mgmt", "")
        if device_info.mgmt_ip:
            obj.add_interface("mgmt", IfaceAddress.FromCIDR(device_info.mgmt_ip))
        return obj


class OLTInfo(BaseModel):
    mac: MACAddressStr
    hostname: str
    mgmt_ip: str
    operational_status: str
    status: Union[int, str, None]
    last_seen: Union[str, None]

    @validator("mac")
    def validate_mac(cls, v) -> Optional[str]:
        return MACAddressStr(v)


class ONUStatus(BaseModel):
    signal: str
    status: Union[int, str, None]
    phase_state: str
    last_seen: Union[str, None]
    uptime: Union[str, None]


class FiberInfo(BaseModel):
    hostname: str
    serial: str
    device_mac: MACAddressStr
    profile: str
    l1_splitter: Union[str, None]
    l2_splitter: Union[str, None]
    otb: Union[str, None]
    olt: Union[OLTInfo, None]
    gpon_name: str
    profile_id: str
    status: Union[ONUStatus, None]

    @validator("device_mac")
    def validate_mac(cls, v) -> Optional[str]:
        return MACAddressStr(v)
