"""
Network Security Scanner - Core logic
Zero external dependencies. Solo librería estándar Python 3.
"""
import socket
import subprocess
import platform
import time
import re
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ─── Common ports ────────────────────────────────────────────────────────────
COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    135:  "MSRPC",
    139:  "NetBIOS",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    993:  "IMAPS",
    995:  "POP3S",
    1433: "MSSQL",
    1521: "Oracle DB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "Jupyter",
    9200: "Elasticsearch",
    27017:"MongoDB",
}

RISK = {
    21: "high", 23: "critical", 25: "medium", 135: "high",
    139: "high", 445: "critical", 1433: "high", 1521: "high",
    3389: "high", 5900: "high", 6379: "high", 27017: "high",
    9200: "high",
}


# ─── Port scanning ───────────────────────────────────────────────────────────
def check_port(host: str, port: int, timeout: float = 0.8) -> dict:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            is_open = s.connect_ex((host, port)) == 0
    except Exception:
        is_open = False
    return {
        "port": port,
        "service": COMMON_PORTS.get(port, "Unknown"),
        "open": is_open,
        "risk": RISK.get(port, "low") if is_open else "none",
    }


def scan_ports(host: str = "127.0.0.1") -> list:
    results = []
    with ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(check_port, host, p): p for p in COMMON_PORTS}
        for f in as_completed(futures):
            results.append(f.result())
    return sorted(results, key=lambda x: x["port"])


# ─── Firewall ────────────────────────────────────────────────────────────────
def get_firewall_status() -> dict:
    os_name = platform.system()
    status = {"active": False, "name": "Desconocido", "details": []}

    def run(cmd):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return r.returncode, r.stdout, r.stderr
        except FileNotFoundError:
            return -1, "", "not found"
        except Exception as e:
            return -1, "", str(e)

    if os_name == "Linux":
        # Try ufw
        code, out, _ = run(["ufw", "status"])
        if code == 0:
            active = "active" in out.lower()
            return {
                "active": active,
                "name": "UFW (Uncomplicated Firewall)",
                "details": [l.strip() for l in out.splitlines() if l.strip()][:10],
            }
        # Try iptables
        code, out, _ = run(["iptables", "-L", "-n"])
        if code == 0:
            lines = [l for l in out.splitlines() if l.strip()]
            # More than default 3 chains = rules exist
            has_rules = any("ACCEPT" in l or "DROP" in l or "REJECT" in l
                            for l in lines if not l.startswith("Chain"))
            return {
                "active": has_rules,
                "name": "iptables",
                "details": lines[:10],
            }
        # Try nft
        code, out, _ = run(["nft", "list", "ruleset"])
        if code == 0:
            lines = [l for l in out.splitlines() if l.strip()]
            return {
                "active": bool(lines),
                "name": "nftables",
                "details": lines[:10],
            }
        status["details"] = ["No se encontró UFW, iptables ni nftables"]

    elif os_name == "Darwin":
        code, out, _ = run(["pfctl", "-s", "info"])
        active = "enabled" in out.lower()
        status = {"active": active, "name": "pf (macOS Firewall)",
                  "details": out.splitlines()[:6]}

    elif os_name == "Windows":
        code, out, _ = run(["netsh", "advfirewall", "show", "allprofiles", "state"])
        active = "on" in out.lower()
        status = {"active": active, "name": "Windows Defender Firewall",
                  "details": out.splitlines()[:8]}

    return status


# ─── Network interfaces (sin psutil) ─────────────────────────────────────────
def get_network_interfaces() -> list:
    interfaces = []
    os_name = platform.system()

    if os_name == "Linux":
        try:
            # Read from /proc/net/if_inet6 and /proc/net/dev
            iface_names = set()
            with open("/proc/net/dev") as f:
                for line in f.readlines()[2:]:
                    name = line.split(":")[0].strip()
                    if name:
                        iface_names.add(name)

            for iface in sorted(iface_names):
                ipv4 = None
                try:
                    r = subprocess.run(["ip", "addr", "show", iface],
                                       capture_output=True, text=True, timeout=3)
                    for line in r.stdout.splitlines():
                        line = line.strip()
                        if line.startswith("inet "):
                            ipv4 = line.split()[1].split("/")[0]
                            break
                except Exception:
                    pass

                up = False
                try:
                    with open(f"/sys/class/net/{iface}/operstate") as f:
                        up = f.read().strip() == "up"
                except Exception:
                    pass

                interfaces.append({
                    "name": iface, "ipv4": ipv4, "ipv6": None,
                    "up": up, "speed": 0,
                })
        except Exception as e:
            interfaces = [{"name": "error", "ipv4": str(e), "ipv6": None, "up": False, "speed": 0}]
    else:
        # Fallback: socket hostname
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            interfaces = [{"name": "eth0", "ipv4": ip, "ipv6": None, "up": True, "speed": 0}]
        except Exception:
            interfaces = []

    return interfaces


# ─── Active connections (sin psutil) ─────────────────────────────────────────
def get_active_connections() -> list:
    conns = []
    os_name = platform.system()

    try:
        if os_name == "Linux":
            # Read /proc/net/tcp
            def hex_to_addr(hex_str):
                ip_hex, port_hex = hex_str.split(":")
                # Little-endian IP
                ip = ".".join(str(int(ip_hex[i:i+2], 16))
                              for i in reversed(range(0, 8, 2)))
                port = int(port_hex, 16)
                return ip, port

            tcp_files = ["/proc/net/tcp", "/proc/net/tcp6"]
            pid_map = {}
            # Build pid->process map from /proc
            try:
                for pid in os.listdir("/proc") if False else []:
                    pass
                import os as _os
                for pid_str in _os.listdir("/proc"):
                    if not pid_str.isdigit():
                        continue
                    try:
                        with open(f"/proc/{pid_str}/comm") as f:
                            pid_map[int(pid_str)] = f.read().strip()
                    except Exception:
                        pass
            except Exception:
                pass

            for tcp_file in tcp_files:
                try:
                    with open(tcp_file) as f:
                        for line in f.readlines()[1:]:
                            parts = line.split()
                            if len(parts) < 4:
                                continue
                            state = parts[3]
                            if state != "01":  # 01 = ESTABLISHED
                                continue
                            local_ip, local_port = hex_to_addr(parts[1])
                            rem_ip, rem_port = hex_to_addr(parts[2])
                            conns.append({
                                "local": f"{local_ip}:{local_port}",
                                "remote": f"{rem_ip}:{rem_port}",
                                "status": "ESTABLISHED",
                                "pid": None,
                                "process": "—",
                            })
                except Exception:
                    pass
        else:
            # Fallback: netstat
            r = subprocess.run(["netstat", "-tn"], capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                if "ESTABLISHED" in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        conns.append({
                            "local": parts[3],
                            "remote": parts[4],
                            "status": "ESTABLISHED",
                            "pid": None,
                            "process": "—",
                        })
    except Exception as e:
        conns = [{"local": "—", "remote": "—",
                  "status": f"Error: {e}", "pid": None, "process": "—"}]

    return conns[:20]


# ─── System info ─────────────────────────────────────────────────────────────
def get_system_info() -> dict:
    ram_gb = 0
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    ram_gb = round(int(line.split()[1]) / 1e6, 1)
                    break
    except Exception:
        pass

    cpu_count = 0
    try:
        with open("/proc/cpuinfo") as f:
            cpu_count = sum(1 for l in f if l.startswith("processor"))
    except Exception:
        import os
        cpu_count = os.cpu_count() or 0

    return {
        "hostname": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()}",
        "arch": platform.machine(),
        "cpu_count": cpu_count,
        "ram_gb": ram_gb,
    }


# ─── Connected devices (ARP + ping sweep) ────────────────────────────────────
def _get_local_subnet() -> str | None:
    """Detecta la subred local de la interfaz principal."""
    try:
        # Obtener IP local
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        # Asumir /24
        parts = local_ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}"
    except Exception:
        return None


def _ping(ip: str) -> bool:
    """Ping rápido a una IP."""
    try:
        r = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            capture_output=True, timeout=2
        )
        return r.returncode == 0
    except Exception:
        return False


def _get_mac_vendor(mac: str) -> str:
    """Prefijo del fabricante basado en los primeros 3 octetos del MAC."""
    vendors = {
        "00:50:56": "VMware", "00:0c:29": "VMware", "00:1c:14": "VMware",
        "52:54:00": "QEMU/KVM", "b8:27:eb": "Raspberry Pi",
        "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
        "00:1a:11": "Google", "f4:f5:d8": "Google",
        "ac:de:48": "Apple", "00:17:f2": "Apple", "3c:15:c2": "Apple",
        "00:50:ba": "D-Link", "00:1e:58": "D-Link",
        "00:23:69": "Cisco", "00:1b:54": "Cisco", "fc:fb:fb": "Cisco",
        "00:19:5b": "Netgear", "20:e5:2a": "Netgear",
        "00:90:4c": "Epson", "00:26:b9": "Dell",
        "00:1d:09": "Dell", "18:03:73": "Dell",
        "00:21:70": "Samsung", "8c:77:12": "Samsung",
        "00:22:68": "Hewlett-Packard", "00:25:b3": "HP",
    }
    prefix = mac[:8].lower()
    for k, v in vendors.items():
        if prefix == k.lower():
            return v
    return "Desconocido"


def _read_arp_table() -> list:
    """Lee la tabla ARP del sistema."""
    devices = []
    try:
        # Linux: /proc/net/arp
        with open("/proc/net/arp") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) < 4:
                    continue
                ip  = parts[0]
                mac = parts[3]
                iface = parts[5] if len(parts) > 5 else "?"
                if mac == "00:00:00:00:00:00":
                    continue
                hostname = "—"
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except Exception:
                    pass
                devices.append({
                    "ip": ip,
                    "mac": mac,
                    "hostname": hostname,
                    "vendor": _get_mac_vendor(mac),
                    "iface": iface,
                    "reachable": True,
                })
    except Exception:
        pass
    return devices


def get_connected_devices(sweep: bool = False) -> list:
    """
    Retorna dispositivos en la red local.
    1. Lee tabla ARP (instantáneo)
    2. Opcionalmente hace ping sweep /24 para poblar ARP (más lento)
    """
    if sweep:
        subnet = _get_local_subnet()
        if subnet:
            # Ping sweep en paralelo (excluye .0 y .255)
            ips = [f"{subnet}.{i}" for i in range(1, 255)]
            with ThreadPoolExecutor(max_workers=60) as ex:
                list(ex.map(_ping, ips))  # solo para poblar ARP, descartamos resultados
            time.sleep(0.5)  # Esperar que el kernel actualice ARP

    devices = _read_arp_table()

    # Deduplicar por IP
    seen = set()
    unique = []
    for d in devices:
        if d["ip"] not in seen:
            seen.add(d["ip"])
            unique.append(d)

    return sorted(unique, key=lambda x: list(map(int, x["ip"].split("."))))


# ─── Full scan ────────────────────────────────────────────────────────────────
def full_scan(target: str = "127.0.0.1") -> dict:
    start = time.time()
    data = {
        "target": target,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "system": get_system_info(),
        "firewall": get_firewall_status(),
        "ports": scan_ports(target),
        "interfaces": get_network_interfaces(),
        "connections": get_active_connections(),
        "devices": get_connected_devices(sweep=False),
        "duration_s": 0,
    }
    data["duration_s"] = round(time.time() - start, 2)

    open_ports = [p for p in data["ports"] if p["open"]]
    data["summary"] = {
        "open_ports": len(open_ports),
        "critical": sum(1 for p in open_ports if p["risk"] == "critical"),
        "high":     sum(1 for p in open_ports if p["risk"] == "high"),
        "medium":   sum(1 for p in open_ports if p["risk"] == "medium"),
        "low":      sum(1 for p in open_ports if p["risk"] == "low"),
        "devices":  len(data["devices"]),
    }
    return data


if __name__ == "__main__":
    import json
    print(json.dumps(full_scan(), indent=2))
