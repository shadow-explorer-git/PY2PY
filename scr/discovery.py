# discovery.py
import ipaddress
import asyncio
import socket
import time
import ifaddr
from typing import List, Dict
from zeroconf import IPVersion, ServiceBrowser, ServiceInfo, Zeroconf, ServiceListener

SERVICE_TYPE = "_p2pxfer._tcp.local."


def get_default_lan_ip() -> str | None:
    """
    Tries to determine the primary LAN IP address that is used for outbound connections.
    This is a heuristic and may not work in all network configurations (e.g., multi-homed systems).
    """
    try:
        # We don't need to actually send data, just connect to get the local endpoint.
        # Using a public DNS server is a common and reliable way to find the default outbound IP.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # The target address doesn't have to be reachable.
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            # Ensure it's not a loopback if the system is offline
            if ip and not ip.startswith("127."):
                return ip
    except OSError:
        # This can fail if there's no network connection, etc.
        pass
    return None

def get_local_interfaces(perform_bind_check: bool = False) -> list[dict]:
    """
    List LAN adapters as (name, IP Address), intelligently sorted to prioritize
    physical and common LAN interfaces over virtual or special-purpose ones.
    :param perform_bind_check: If True, proactively checks if an IP is bindable, filtering out "ghost" IPs.
    """
    interfaces_with_metadata = []
    seen = set()
    default_ip = get_default_lan_ip()

    # Keywords to identify adapters that are likely virtual or not useful for general LAN sharing.
    # These will be sorted to the bottom of the list.
    VIRTUAL_ADAPTER_KEYWORDS = {
        "virtual", "vmware", "vbox", "vnic", "vpn", "teredo", "isatap",
        "loopback", "docker", "veth", "wsl", "tap", "tun", "hyper-v", "pseudo",
    }

    for adapter in ifaddr.get_adapters():
        # Pre-check the adapter name against keywords to determine if it's likely virtual.
        adapter_name_lower = adapter.nice_name.lower()
        is_virtual_adapter = any(keyword in adapter_name_lower for keyword in VIRTUAL_ADAPTER_KEYWORDS)

        for address in adapter.ips:
            ip = address.ip
            if not isinstance(ip, str):
                continue

            try:
                # Strip IPv6 scope ID (e.g., %eth0) if present, as it's not part of the address.
                if '%' in ip:
                    ip = ip.split('%')[0]

                ip_obj = ipaddress.ip_address(ip)

                if ip_obj.is_loopback or ip_obj.is_unspecified:
                    continue

                if perform_bind_check:
                    # Proactively check if the IP is bindable. This filters out "ghost" IPs
                    # from disconnected or virtual adapters that can't be used.
                    can_bind = False
                    try:
                        family = socket.AF_INET6 if isinstance(ip_obj, ipaddress.IPv6Address) else socket.AF_INET
                        with socket.socket(family, socket.SOCK_STREAM) as s:
                            s.bind((ip, 0))  # Bind to a random free port
                        can_bind = True
                    except OSError:
                        pass  # Cannot bind, so we'll skip this IP.
                    if not can_bind:
                        continue

                if (adapter.nice_name, ip) in seen:
                    continue
                seen.add((adapter.nice_name, ip))

                # An interface is "undesirable" if it's likely virtual or uses a link-local address.
                is_undesirable = is_virtual_adapter or ip_obj.is_link_local

                interfaces_with_metadata.append({
                    "name": adapter.nice_name, "ip": ip,
                    "is_default": ip == default_ip,
                    "is_undesirable": is_undesirable,
                    "is_ipv6": isinstance(ip_obj, ipaddress.IPv6Address),
                })
            except ValueError:
                continue

    # Sort using a multi-level key to rank interfaces by desirability.
    interfaces_with_metadata.sort(key=lambda item: (
        not item["is_default"],  # 1. Default IP comes first.
        item["is_undesirable"],  # 2. Desirable interfaces come before undesirable ones.
        item["is_ipv6"],         # 3. IPv4 addresses come before IPv6.
        item["name"].casefold(), # 4. Sort by adapter name.
        item["ip"],              # 5. Sort by IP as a final tie-breaker.
    ))

    # Format the list for the UI, stripping the sorting metadata.
    if not interfaces_with_metadata:
        return [{
            "name": "Loopback", "ip": "127.0.0.1",
            "is_default": False, "is_undesirable": True, "is_ipv6": False
        }]

    return interfaces_with_metadata

class ReceiverAnnouncer:
    """Runs on the Receiving device. Announces presence to the network."""
    def __init__(self, port: int, device_name: str, ip_address: str | None = None, interface_ip: str | None = None, on_status=None):
        kwargs = {"ip_version": IPVersion.All}
        self.on_status = on_status
        resolved_interface = interface_ip or ip_address
        if resolved_interface:
            try:
                ipaddress.ip_address(resolved_interface)
            except ValueError:
                resolved_interface = None
            else:
                ip_obj = ipaddress.ip_address(resolved_interface)
                if not ip_obj.is_loopback:
                    kwargs["interfaces"] = [resolved_interface]
        self.zeroconf = Zeroconf(**kwargs)
        self.ip = ip_address or "127.0.0.1"
        self.port = port
        
        # Service details that the sender will see. Support IPv4 and IPv6 packed addresses.
        try:
            addr_bytes = socket.inet_aton(self.ip)
        except OSError:
            try:
                addr_bytes = socket.inet_pton(socket.AF_INET6, self.ip)
            except OSError:
                # Fallback to loopback IPv4
                addr_bytes = socket.inet_aton('127.0.0.1')

        self.info = ServiceInfo(
            SERVICE_TYPE,
            f"{device_name}.{SERVICE_TYPE}",
            addresses=[addr_bytes],
            port=self.port,
            properties={'status': 'ready_to_receive'},
            server=f"{device_name}.local.",
        )

    def _status(self, key: str, **kwargs):
        if self.on_status:
            self.on_status(key, **kwargs)
        else:
            # Fallback for CLI usage, format a simple string
            message = key.replace('_', ' ').capitalize()
            if kwargs:
                message += ": " + ", ".join(f"{k}={v}" for k, v in kwargs.items())
            print(message)

    async def start_async(self):
        """Asynchronously starts the announcer."""
        self._status("status_announcing_as_receiver", ip=self.ip, port=self.port)
        await asyncio.to_thread(self.zeroconf.register_service, self.info)

    def start(self):
        """Synchronously starts the announcer."""
        self._status("status_announcing_as_receiver", ip=self.ip, port=self.port)
        self.zeroconf.register_service(self.info)

    async def stop_async(self):
        """Asynchronously stops the announcer."""
        self._status("status_stopping_announcement")
        await asyncio.to_thread(self.zeroconf.unregister_service, self.info)
        await asyncio.to_thread(self.zeroconf.close)

    def stop(self):
        """Synchronously stops the announcer."""
        self._status("status_stopping_announcement")
        self.zeroconf.unregister_service(self.info)
        self.zeroconf.close()

class SenderScanner(ServiceListener):
    # PATCH: Added on_device_lost to the signature
    def __init__(self, on_device_found=None, on_device_lost=None, interface_ip: str | None = None, on_status=None):
        kwargs = {"ip_version": IPVersion.All}
        if interface_ip:
            try:
                ip_obj = ipaddress.ip_address(interface_ip)
                if not ip_obj.is_loopback:
                    kwargs["interfaces"] = [interface_ip]
            except ValueError:
                pass  # Ignore invalid IP string
        self.on_status = on_status
        self.zeroconf = Zeroconf(**kwargs)
        self.interface_ip = interface_ip
        self.found_devices = {}
        self.browser = None
        self.on_device_found = on_device_found
        self.on_device_lost = on_device_lost  # PATCH: Store the lost callback

    def _status(self, key: str, **kwargs):
        if self.on_status:
            self.on_status(key, **kwargs)
        else:
            # Fallback for CLI usage, format a simple string
            message = key.replace('_', ' ').capitalize()
            if kwargs:
                message += ": " + ", ".join(f"{k}={v}" for k, v in kwargs.items())
            print(message)

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        if name in self.found_devices:
            # PATCH: Clean up the service type suffix to get the raw device name
            device_name = name.replace(f".{SERVICE_TYPE}", "")
            self._status("status_receiver_disconnected", name=device_name)
            del self.found_devices[name]
            # PATCH: Notify the Flet UI so it can clear it from the list
            if self.on_device_lost:
                self.on_device_lost(device_name)

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        info = zc.get_service_info(type_, name)
        if info:
            # Support IPv4 and IPv6 addresses in service info
            raw = info.addresses[0]
            try:
                ip = socket.inet_ntoa(raw)
            except OSError:
                try:
                    ip = socket.inet_ntop(socket.AF_INET6, raw)
                except Exception:
                    ip = ''
            device_name = name.replace(f".{SERVICE_TYPE}", "")
            self.found_devices[name] = {'ip': ip, 'port': info.port, 'name': device_name}
            self._status("status_found_receiver_details", name=device_name, ip=ip, port=info.port)
            if self.on_device_found:
                self.on_device_found(device_name, ip, info.port)

    async def start_scanning_async(self):
        # The ServiceBrowser constructor can block, so run it in a thread.
        self.browser = await asyncio.to_thread(ServiceBrowser, self.zeroconf, SERVICE_TYPE, self)

    def start_scanning(self):
        # This is a blocking call, intended for CLI/sync usage.
        self.browser = ServiceBrowser(self.zeroconf, SERVICE_TYPE, self)

    async def stop_scanning_async(self):
        if self.browser:
            await asyncio.to_thread(self.browser.cancel)
        await asyncio.to_thread(self.zeroconf.close)

    def stop_scanning(self):
        if self.browser:
            self.browser.cancel()
        self.zeroconf.close()


class SubnetScanner:
    """Performs a quick unicast scan of a subnet to find open ports."""

    def __init__(self, on_device_found=None, on_scan_complete=None, on_status=None):
        self.on_device_found = on_device_found
        self.on_scan_complete = on_scan_complete
        self.on_status = on_status
        self.port = 35000  # Default port, can be overridden by scan()
        self._tasks = []
        self._cancelled = False

    def _status(self, key: str, **kwargs):
        if self.on_status:
            self.on_status(key, **kwargs)
        else:
            # Fallback for CLI usage, format a simple string
            message = key.replace('_', ' ').capitalize()
            if kwargs:
                message += ": " + ", ".join(f"{k}={v}" for k, v in kwargs.items())
            print(message)

    def cancel(self):
        """Cancels the running scan."""
        self._cancelled = True
        for task in self._tasks:
            task.cancel()

    async def _probe(self, ip: str):
        if self._cancelled:
            return
        try:
            # Short timeout to avoid waiting long for non-responsive hosts
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, self.port), timeout=1.0
            )
            writer.close()
            await writer.wait_closed()
            if self.on_device_found and not self._cancelled:
                # In manual mode, we use the IP as the "name" for display purposes.
                self.on_device_found(ip, ip, self.port)
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            # Host is not reachable or port is closed, which is expected for most IPs.
            pass
        except Exception:
            # Other unexpected errors
            pass

    async def scan(self, subnet_str: str, port: int = 35000):
        self.port = port
        self._cancelled = False
        self._tasks = []
        try:
            network = ipaddress.ip_network(subnet_str, strict=False)
            for ip in network.hosts():
                task = asyncio.create_task(self._probe(str(ip)))
                self._tasks.append(task)
            await asyncio.gather(*self._tasks, return_exceptions=True)
        except ValueError:
            self._status("status_invalid_subnet_format", subnet=subnet_str)
        finally:
            if self.on_scan_complete and not self._cancelled:
                self.on_scan_complete()

# --- CLI Test Block ---
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2 or sys.argv[1] not in ['send', 'receive']:
        print("Usage: python discovery.py [send|receive]")
        sys.exit(1)

    mode = sys.argv[1]

    if mode == 'receive':
        # Simulated port 35000 for the eventual asyncio server
        announcer = ReceiverAnnouncer(port=35000, device_name="MyLaptop")
        try:
            announcer.start()
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            announcer.stop()

    elif mode == 'send':
        scanner = SenderScanner()
        try:
            scanner.start_scanning()
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            scanner.stop_scanning()
