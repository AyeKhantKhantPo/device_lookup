from subprocess import CalledProcessError

import structlog
from anyio import run_process
from netaddr import IPNetwork
from netaddr.core import AddrFormatError

log = structlog.get_logger()


async def ping_to_ip(host_ip: str) -> bool:
    host_alive = True
    try:
        ipnet = IPNetwork(host_ip)
    except AddrFormatError as e:
        log.error("Ping to IP.", ip_address=host_ip, error=e)
        raise

    try:
        _ = await run_process(f"timeout 2 ping -i 0.2 -c 1 -w 1 {str(ipnet.ip)}")
    except CalledProcessError as e:
        log.error("Ping to IP.", ip_address=host_ip, error=e)
        host_alive = False
    return host_alive
