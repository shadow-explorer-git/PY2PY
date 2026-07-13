import socket
import time
import ifaddr
from typing import List, Dict
from zeroconf import IPVersion, ServiceBrowser, ServiceInfo, Zeroconf, ServiceListener

SERVICE_TYPE = "_p2pxfer._tcp.local."

def get_local_ip() -> str:
    """Utility to get the active local IP address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't have to be reachable, just forces socket to resolve local IP
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip


def get_local_ipv4_addresses() -> list[str]:
    """Returns usable local IPv4 addresses for the receiver's LAN selector."""
    addresses = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            address = info[4][0]
            if not address.startswith("127."):
                addresses.add(address)
    except socket.gaierror:
        pass
    preferred = get_local_ip()
    if not preferred.startswith("127."):
        addresses.add(preferred)
    return sorted(addresses) or ["127.0.0.1"]


def get_local_interfaces() -> list[tuple[str, str]]:
    """List LAN adapters as (name, IPv4), preferring the active internet path."""
    preferred_ip = get_local_ip()
    interfaces = []
    for adapter in ifaddr.get_adapters():
        for address in adapter.ips:
            ip = address.ip
            if not isinstance(ip, str) or ip.startswith("127.") or ip.startswith("169.254."):
                continue
            interfaces.append((adapter.nice_name, ip))
    unique = list(dict.fromkeys(interfaces))
    unique.sort(key=lambda item: (item[1] != preferred_ip, item[0].casefold(), item[1]))
    return unique or [("Loopback (local only)", "127.0.0.1")]

class ReceiverAnnouncer:
    """Runs on the Receiving device. Announces presence to the network."""
    def __init__(self, port: int, device_name: str, ip_address: str | None = None):
        # Updated to IPVersion.All for both IPv4 and IPv6
        self.zeroconf = Zeroconf(ip_version=IPVersion.All)
        self.ip = ip_address or get_local_ip()
        self.port = port
        
        # Service details that the sender will see
        self.info = ServiceInfo(
            SERVICE_TYPE,
            f"{device_name}.{SERVICE_TYPE}",
            addresses=[socket.inet_aton(self.ip)],
            port=self.port,
            properties={'status': 'ready_to_receive'},
            server=f"{device_name}.local.",
        )

    def start(self):
        print(f"[+] Announcing device on {self.ip}:{self.port} as a Receiver...")
        self.zeroconf.register_service(self.info)

    def stop(self):
        print("[-] Stopping announcement...")
        self.zeroconf.unregister_service(self.info)
        self.zeroconf.close()


class SenderScanner(ServiceListener):
    # Add the callback to init
    def __init__(self, on_device_found=None, interface_ip: str | None = None):
        # Restrict discovery to the selected IPv4 LAN adapter when requested.
        kwargs = {"ip_version": IPVersion.V4Only}
        if interface_ip:
            kwargs["interfaces"] = [interface_ip]
        self.zeroconf = Zeroconf(**kwargs)
        self.interface_ip = interface_ip
        self.found_devices = {}
        self.browser = None
        self.on_device_found = on_device_found

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        if name in self.found_devices:
            print(f"\n[-] Device left the network: {name}")
            del self.found_devices[name]

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        info = zc.get_service_info(type_, name)
        if info:
            ip = socket.inet_ntoa(info.addresses[0])
            device_name = name.replace(f".{SERVICE_TYPE}", "")
            self.found_devices[name] = {'ip': ip, 'port': info.port, 'name': device_name}
            print(f"\n[+] Found Receiver: {device_name} at {ip}:{info.port}")
            if self.on_device_found:
                self.on_device_found(device_name, ip, info.port)

    def start_scanning(self):
        target = self.interface_ip or "all interfaces"
        print(f"[*] Scanning for receivers on {target} (Press Ctrl+C to stop)...")
        self.browser = ServiceBrowser(self.zeroconf, SERVICE_TYPE, self)

    def stop_scanning(self):
        if self.browser:
            self.browser.cancel()
        self.zeroconf.close()

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
