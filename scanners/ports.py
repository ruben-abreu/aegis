import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

GREEN="\033[92m"; RED="\033[91m"; YELLOW="\033[93m"; BOLD="\033[1m"; END="\033[0m"

def ok(msg): print(f"{GREEN}[✓]{END} {msg}")
def warn(msg): print(f"{YELLOW}[!]{END} {msg}")
def bad(msg): print(f"{RED}[✗]{END} {msg}")

UDP_PORTS = {
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    123: "NTP",
    161: "SNMP",
    162: "SNMP Trap",
    389: "LDAP",
    5353: "mDNS",
}

PORT_DEFINITIONS = {
    "Web Services": {
        80: "HTTP",
        8080: "HTTP (alt)",
        8000: "HTTP (alt)",
        8888: "HTTP (alt)",
        443: "HTTPS",
        8443: "HTTPS (alt)",
    },
    "SSH & Remote Access": {
        22: "SSH",
        3389: "RDP (Windows Remote Desktop)",
        5900: "VNC",
        5901: "VNC (alt)",
        3306: "MySQL",
        5432: "PostgreSQL",
    },
    "Email Services": {
        25: "SMTP",
        110: "POP3",
        143: "IMAP",
        465: "SMTPS",
        587: "SMTP (submission)",
        993: "IMAPS",
        995: "POP3S",
    },
    "DNS & Network": {
        53: "DNS",
        67: "DHCP",
        68: "DHCP",
        123: "NTP",
        161: "SNMP",
        162: "SNMP Trap",
    },
    "Databases": {
        3306: "MySQL",
        5432: "PostgreSQL",
        27017: "MongoDB",
        27018: "MongoDB (alt)",
        6379: "Redis",
        1433: "MSSQL",
        1521: "Oracle",
    },
    "Messaging & Chat": {
        5672: "AMQP (RabbitMQ)",
        6667: "IRC",
        6697: "IRC (SSL)",
    },
    "File Transfer": {
        21: "FTP",
        22: "SSH/SFTP",
        445: "SMB/CIFS",
        139: "NetBIOS",
        873: "rsync",
    },
    "Other Services": {
        23: "Telnet (deprecated)",
        69: "TFTP",
        79: "Finger",
        111: "Portmap",
        389: "LDAP",
        636: "LDAPS",
        8008: "HTTP (alt)",
        9000: "SonarQube",
        9200: "Elasticsearch",
        9300: "Elasticsearch (node)",
        11211: "Memcached",
        27016: "MongoDB (alt)",
    }
}

def test_port(host, port, protocol="tcp", timeout=3):
    try:
        if protocol.lower() == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            try:
                sock.sendto(b"", (host, port))
                sock.recvfrom(1024)
                sock.close()
                return True
            except socket.timeout:
                sock.close()
                return True
            except Exception:
                sock.close()
                return False
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
    except Exception:
        return False

def get_port_service(port):
    for category, ports in PORT_DEFINITIONS.items():
        if port in ports:
            return ports[port], category
    return None, None

def run(target, target_type=None, port=None):
    print("=" * 50)
    print(" OPEN PORT SCAN")
    print(f" Target: {target}")
    print(f" Port: {port}")
    print("=" * 50)

    if not port:
        bad("No port specified")
        return

    protocol = "tcp"
    port_num = port

    if isinstance(port, str) and "/" in str(port):
        parts = str(port).split("/")
        port_num = int(parts[0])
        protocol = parts[1].lower()
    else:
        port_num = int(port)
        if port_num in UDP_PORTS:
            protocol = "udp"
            warn(f"Port {port_num} is commonly UDP ({UDP_PORTS[port_num]}) - checking UDP instead")

    print(f"\n[*] Checking port {port_num}/{protocol.upper()}...\n")

    is_open = test_port(target, port_num, protocol=protocol, timeout=5)
    service, category = get_port_service(port_num)

    if is_open:
        if service:
            ok(f"Port {port_num}/{protocol.upper()} is OPEN - {service} ({category})")
        else:
            ok(f"Port {port_num}/{protocol.upper()} is OPEN - Unknown service")
    else:
        bad(f"Port {port_num}/{protocol.upper()} is CLOSED or filtered")

    print("\n" + "=" * 50)
