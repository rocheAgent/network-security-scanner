"""
Network Security Scanner - Core logic
Zero external dependencies. Solo librería estándar Python 3.
"""
import socket
import subprocess
import platform
import time
import re
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
    }
    return data


if __name__ == "__main__":
    import json
    print(json.dumps(full_scan(), indent=2))
