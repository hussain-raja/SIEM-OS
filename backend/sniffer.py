import requests
import time
import threading
import win32evtlog  
import win32security
import pywintypes   
import random
from scapy.all import sniff, IP, IPv6, TCP, conf, Raw, get_if_list, get_if_addr
import json
import subprocess
from datetime import datetime

# --- NETWORK CONFIGURATION ---
SIEM_IP = "hussain-2003-siem-backend-v2.hf.space" 
API_URL = f"https://{SIEM_IP}/logs"
STATUS_URL = f"https://{SIEM_IP}/sensor/status"
INTEL_URL = f"https://{SIEM_IP}/intel" 
BLOCKED_IPS_URL = f"https://{SIEM_IP}/blocked-ips" # Add this explicitly

conf.L3socket = conf.L3socket

# --- CONFIGURATION ---
DEBUG_MODE = True  
HONEYPOT_PORTS = [
    21,    # FTP (Unencrypted file transfers)
    22,    # SSH (The #1 target for brute force)
    23,    # Telnet (IoT botnet favorite)
    25,    # SMTP (Email spam relays)
    143,   # IMAP (Mail access)
    445,   # SMB (Windows File Sharing - EternalBlue/Ransomware)
    1433,  # MSSQL (Database attacks)
    3306,  # MySQL (Database attacks)
    3389,  # RDP (Remote Desktop - Huge ransomware entry point)
    5900,  # VNC (Remote desktop)
    8080,  # HTTP Proxy/Alt (Commonly scanned for misconfigurations)
    445,
    80
]
ALERT_COOLDOWN = 10
DOS_THRESHOLD = 50     
SCAN_THRESHOLD = 5     


# ==========================
# Service Classes (Sensor)
# ==========================

class MobilePushAlerts:
    """
    MobilePushAlerts
    - Owns: ntfy topic + sending mobile alerts.

    Private attributes:
    - _topic

    Public operations:
    - push_to_mobile(alert_type, ip, message)
    """

    def __init__(self, *, topic: str):
        self._topic = topic

    def push_to_mobile(self, alert_type, ip, message):
        try:
            requests.post(
                f"https://ntfy.sh/{self._topic}",
                data=f"CRITICAL: {alert_type} from {ip}. {message}".encode("utf-8"),
                headers={"Title": "SIEM.OS INTRUSION", "Priority": "5", "Tags": "rotating_light,skull"},
                timeout=5,
            )
            print(f"📱 Mobile Alert Sent to {self._topic}")
        except Exception as e:
            print(f"❌ Mobile Alert Failed: {e}")


class ThreatIntel:
    """
    ThreatIntel
    - Owns: syncing threat intel cache from backend.

    Private attributes:
    - _intel_url, _debug, _cache

    Public operations:
    - get_cache()
    - sync_loop()
    """

    def __init__(self, *, intel_url: str, debug: bool):
        self._intel_url = intel_url
        self._debug = debug
        self._cache = {}

    def get_cache(self) -> dict:
        return self._cache

    def sync_loop(self):
        while True:
            try:
                r = requests.get(self._intel_url, timeout=5)
                if r.status_code == 200:
                    self._cache = r.json()
            except Exception as e:
                if self._debug:
                    print(f"[-] Intel Sync Error: {e}")
            time.sleep(30)


class GeoEnrichment:
    """
    GeoEnrichment
    - Owns: Geo-IP resolution + enrichment.

    Private attributes:
    - _siem_ip, _threat_intel, _geo_cache

    Public operations:
    - get_geo_location(ip)
    """

    def __init__(self, *, siem_ip: str, threat_intel: ThreatIntel):
        self._siem_ip = siem_ip
        self._threat_intel = threat_intel
        self._geo_cache = {}

    def get_geo_location(self, ip: str):
        if ip in ["127.0.0.1", "::1", "localhost", self._siem_ip] or ip.startswith(
            ("192.168.", "10.", "172.", "fe80:")
        ):
            return {"origin": "Local Network", "actor": "Internal Machine", "status": "Safe/Testing"}

        intel_cache = self._threat_intel.get_cache()
        if ip in intel_cache:
            data = intel_cache[ip]
            return {
                "origin": data.get("origin", "Known Range"),
                "actor": data.get("actor", "Known Threat Actor"),
                "status": data.get("status", "Active"),
            }

        if ip in self._geo_cache:
            return self._geo_cache[ip]

        try:
            r = requests.get(f"http://ip-api.com/json/{ip}", timeout=1).json()
            if r.get("status") == "success":
                intel_obj = {
                    "origin": f"{r['city']}, {r['country']}",
                    "actor": r.get("isp", "External Source"),
                    "status": "Under Observation",
                }
                self._geo_cache[ip] = intel_obj
                return intel_obj
        except Exception:
            print(f"DEBUG: Geo Lookup Timeout for {ip} (API Busy) - Using temporary label")

        return {"origin": "Locating...", "actor": "Gathering Intel", "status": "Pending"}


class ActiveDefense:
    """
    ActiveDefense
    - Owns: firewall synchronization with the cloud blocked-IPs list.

    Private attributes:
    - _blocked_ips_url

    Public operations:
    - sync_firewall_with_cloud()
    - run_firewall_sync()
    """

    def __init__(self, *, blocked_ips_url: str):
        self._blocked_ips_url = blocked_ips_url

    def sync_firewall_with_cloud(self):
        try:
            response = requests.get(self._blocked_ips_url, timeout=10)
            if response.status_code == 200:
                cloud_data = response.json()
                cloud_ips = [item["ip"] for item in cloud_data]
                cloud_ips_set = set(cloud_ips)

                for ip in cloud_ips:
                    rule_name = f"SIEM_BLOCK_{ip}"
                    check_rule = subprocess.run(
                        f'netsh advfirewall firewall show rule name="{rule_name}"',
                        shell=True,
                        capture_output=True,
                        text=True,
                    )
                    if "No rules match" in check_rule.stdout:
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] 🔥 NEW BLOCK: {ip}")
                        subprocess.run(
                            f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}',
                            shell=True,
                            check=True,
                        )

                all_rules = subprocess.run(
                    "netsh advfirewall firewall show rule name=all",
                    shell=True,
                    capture_output=True,
                    text=True,
                )
                for line in all_rules.stdout.splitlines():
                    if "Rule Name:" in line and "SIEM_BLOCK_" in line:
                        local_ip = line.split("SIEM_BLOCK_")[-1].strip()
                        if local_ip not in cloud_ips_set:
                            print(f"[{datetime.now().strftime('%H:%M:%S')}] 🔓 UNBLOCKING: {local_ip}")
                            subprocess.run(
                                f'netsh advfirewall firewall delete rule name="SIEM_BLOCK_{local_ip}"',
                                shell=True,
                                check=True,
                            )
            else:
                print(f"⚠️ Cloud sync failed. Status: {response.status_code}")
        except Exception as e:
            print(f"[-] Firewall Sync Error: {e}")

    def run_firewall_sync(self):
        while True:
            self.sync_firewall_with_cloud()
            time.sleep(30)


class NetworkAgent:
    """
    NetworkAgent
    - Owns: scapy sniffing + DPI logic + event emission.

    Private attributes:
    - _api_url, _geo, _dos_threshold, _scan_threshold, _honeypot_ports
    - _packet_counts, _port_scan_counts, _last_alert_time, _flow_tracker

    Public operations:
    - send_to_siem(data)
    - process_packet(pkt)
    - start_sniffing()
    """

    def __init__(self, *, api_url: str, geo: GeoEnrichment, dos_threshold: int, scan_threshold: int, honeypot_ports: list):
        self._api_url = api_url
        self._geo = geo
        self._dos_threshold = dos_threshold
        self._scan_threshold = scan_threshold
        self._honeypot_ports = honeypot_ports

        self._packet_counts = {}
        self._port_scan_counts = {}
        self._last_alert_time = {}
        self._flow_tracker = {}

    def send_to_siem(self, data):
        if not data or not isinstance(data, list):
            return

        event_type = data[0]["event_type"]
        current_time = time.time()

        if event_type in self._last_alert_time:
            if current_time - self._last_alert_time[event_type] < 1:
                return

        try:
            if "origin" in data[0]:
                data[0]["location"] = data[0]["origin"]

            headers = {"User-Agent": "SIEM-Sensor-v1", "Content-Type": "application/json"}

            data[0]["packet_size"] = int(data[0].get("packet_size", 0))
            data[0]["flow_duration"] = float(data[0].get("flow_duration", 0.0))
            data[0]["requests_sec"] = int(data[0].get("requests_sec", 0))

            requests.post(self._api_url, json=data, headers=headers, timeout=5)

            log_msg = str(data[0].get("message", "")).upper()
            if any(keyword in log_msg for keyword in ["CRITICAL", "SQL", "TAMPER", "EXPLOIT", "DDOS"]):
                try:
                    ntfy_url = "https://ntfy.sh/siem_alerts_Hussain_1999"
                    display_msg = data[0].get("message", "Threat Detected")
                    src_ip = data[0].get("source_ip", "Unknown IP")
                    body_content = f"Alert: {event_type}\nSource: {src_ip}\nDetails: {display_msg}"

                    requests.post(
                        ntfy_url,
                        data=body_content.encode("utf-8"),
                        headers={"Title": "SIEM INTRUSION DETECTED", "Priority": "5", "Tags": "skull,rotating_light"},
                        timeout=5,
                    )
                    print(f"[+] Mobile Push Sent for {event_type}")
                except Exception as mobile_e:
                    print(f"[-] Mobile Push Failed: {mobile_e}")

            if event_type != "Scanning/Unknown":
                loc_obj = data[0].get("origin", {})
                display = loc_obj.get("origin", "Unknown") if isinstance(loc_obj, dict) else loc_obj
                print(f"[!] SIEM Alert Sent: {event_type} | Origin: {display}")

            self._last_alert_time[event_type] = current_time
        except Exception as e:
            print(f"[-] SIEM Post Error: {e}")

    def process_packet(self, pkt):
        if not pkt.haslayer(IP) and not pkt.haslayer(IPv6):
            return

        src_ip = pkt[IP].src if pkt.haslayer(IP) else pkt[IPv6].src
        dst_port = pkt[TCP].dport if pkt.haslayer(TCP) else None

        if (src_ip == SIEM_IP and dst_port == 8000) or dst_port in [3000, 27017]:
            return

        if pkt.haslayer(Raw):
            payload_raw = str(pkt[Raw].load).upper()
            if "POST /LOGS" in payload_raw or "PYTHON-REQUESTS" in payload_raw:
                return

        current_time = time.time()
        packet_size = len(pkt)

        if src_ip not in self._flow_tracker:
            self._flow_tracker[src_ip] = current_time

        flow_duration = (current_time - self._flow_tracker[src_ip]) * 1000
        if flow_duration > 30000:
            self._flow_tracker[src_ip] = current_time
            flow_duration = 0

        location = self._geo.get_geo_location(src_ip)

        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            scan_type = None
            if flags == 0:
                scan_type = "TCP Null Scan"
            elif flags == 0x29:
                scan_type = "TCP Xmas Scan"
            elif flags == 0x01:
                scan_type = "TCP Fin Scan"

            if scan_type:
                self.send_to_siem(
                    [
                        {
                            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                            "source_ip": src_ip,
                            "origin": location,
                            "event_type": "Stealth Scan",
                            "message": f"Nmap-style {scan_type} detected.",
                            "user": "Network_Sensor",
                            "packet_size": packet_size,
                            "flow_duration": flow_duration,
                            "requests_sec": 1,
                        }
                    ]
                )

        if dst_port:
            if src_ip not in self._port_scan_counts:
                self._port_scan_counts[src_ip] = {"ports": set(), "first_hit": current_time}
            if current_time - self._port_scan_counts[src_ip]["first_hit"] > 10:
                self._port_scan_counts[src_ip] = {"ports": set(), "first_hit": current_time}
            self._port_scan_counts[src_ip]["ports"].add(dst_port)
            if len(self._port_scan_counts[src_ip]["ports"]) >= self._scan_threshold:
                self.send_to_siem(
                    [
                        {
                            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                            "source_ip": src_ip,
                            "origin": location,
                            "event_type": "Port Scan",
                            "message": f"Probed {len(self._port_scan_counts[src_ip]['ports'])} ports.",
                            "user": "Network_Sensor",
                            "packet_size": packet_size,
                            "flow_duration": flow_duration,
                            "requests_sec": 0,
                        }
                    ]
                )

        if dst_port in self._honeypot_ports:
            self.send_to_siem(
                [
                    {
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "source_ip": src_ip,
                        "origin": location,
                        "event_type": "Honeypot Breach",
                        "message": f"Port {dst_port} accessed",
                        "user": "Honeypot_Sensor",
                        "packet_size": packet_size,
                        "flow_duration": flow_duration,
                        "requests_sec": 1,
                    }
                ]
            )
            return

        if src_ip not in self._packet_counts:
            self._packet_counts[src_ip] = []
        self._packet_counts[src_ip].append(current_time)
        self._packet_counts[src_ip] = [t for t in self._packet_counts[src_ip] if current_time - t <= 1]
        requests_sec = len(self._packet_counts[src_ip])
        if requests_sec > self._dos_threshold:
            self.send_to_siem(
                [
                    {
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "source_ip": src_ip,
                        "origin": location,
                        "event_type": "DoS Attack",
                        "message": f"High traffic: {requests_sec} pkts/sec",
                        "user": "Network_Sensor",
                        "packet_size": packet_size,
                        "flow_duration": flow_duration,
                        "requests_sec": requests_sec,
                    }
                ]
            )

        payload = str(pkt[Raw].load).upper() if pkt.haslayer(Raw) else ""
        if any(sig in payload for sig in MALICIOUS_SIGNATURES):
            self.send_to_siem(
                [
                    {
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "source_ip": src_ip,
                        "origin": location,
                        "event_type": "Scanner Detected",
                        "message": "Scanner signature found in payload.",
                        "user": "Network_Sensor",
                        "packet_size": packet_size,
                        "flow_duration": flow_duration,
                        "requests_sec": requests_sec,
                    }
                ]
            )

        if any(p in payload for p in ["' OR", "1=1", "UNION SELECT"]):
            self.send_to_siem(
                [
                    {
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "source_ip": src_ip,
                        "origin": location,
                        "event_type": "SQL Injection",
                        "message": "CRITICAL: SQLi attempt detected",
                        "user": "Network_Sensor",
                        "packet_size": packet_size,
                        "flow_duration": flow_duration,
                        "requests_sec": requests_sec,
                    }
                ]
            )
        elif any(ext in payload for ext in [".EXE", ".PS1", ".BAT"]):
            self.send_to_siem(
                [
                    {
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "source_ip": src_ip,
                        "origin": location,
                        "event_type": "Suspicious File",
                        "message": "CRITICAL: Malicious extension detected",
                        "user": "Network_Sensor",
                        "packet_size": packet_size,
                        "flow_duration": flow_duration,
                        "requests_sec": requests_sec,
                    }
                ]
            )

    def start_sniffing(self):
        from scapy.all import ifaces, sniff as scapy_sniff, conf as scapy_conf

        print("[*] Manual Interface Selection...")
        target_iface = None
        for iface in ifaces.values():
            iface_ip = getattr(iface, "ip", "")
            if "192.168.1.18" == iface_ip or "192.168.1.18" in str(getattr(iface, "ips", [])):
                target_iface = iface
                break

        if not target_iface:
            print("[!] Could not find interface for 192.168.1.18. Falling back to default.")
            target_iface = scapy_conf.iface
        else:
            print(f"[*] SUCCESS: Found active interface: {getattr(target_iface, 'description', target_iface.name)}")

        iface_to_sniff = target_iface.name if hasattr(target_iface, "name") else target_iface
        print(f"[*] Sniffing for external threats on {iface_to_sniff}...")
        try:
            traffic_filter = "tcp port not 443"
            scapy_sniff(iface=iface_to_sniff, prn=self.process_packet, store=0, promisc=True, filter=traffic_filter)
        except Exception as e:
            print(f"[*] Sniffer Error: {e}")


class WindowsAgent:
    """
    WindowsAgent
    - Owns: Windows Security Event monitoring and emitting SIEM alerts.
    """

    def __init__(self, *, send_to_siem):
        self._send_to_siem = send_to_siem
        self._failed_login_counts = {}

    def fetch_windows_logs(self):
        print("[*] Thread Started: Monitoring Windows Security Events...")
        server = "localhost"
        log_type = "Security"
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        while True:
            try:
                hand = win32evtlog.OpenEventLog(server, log_type)
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if events:
                    for event in events:
                        if event.EventID == 4625:
                            user = event.StringInserts[5] if event.StringInserts else "Unknown"
                            self._failed_login_counts[user] = self._failed_login_counts.get(user, 0) + 1
                            if self._failed_login_counts[user] >= 3:
                                self._send_to_siem(
                                    [
                                        {
                                            "timestamp": event.TimeGenerated.isoformat(),
                                            "source_ip": "127.0.0.1",
                                            "origin": {"origin": "Local Machine", "actor": "Win-Auth", "status": "Internal"},
                                            "event_type": "Brute Force Attempt",
                                            "message": f"CRITICAL: Multiple login failures for user: {user}. Potential EXPLOIT.",
                                            "user": user,
                                            "packet_size": 0,
                                            "flow_duration": 0,
                                            "requests_sec": 0,
                                        }
                                    ]
                                )
                                self._failed_login_counts[user] = 0

                        elif event.EventID == 1102:
                            self._send_to_siem(
                                [
                                    {
                                        "timestamp": event.TimeGenerated.isoformat(),
                                        "source_ip": "127.0.0.1",
                                        "origin": {"origin": "Local Machine", "actor": "System", "status": "Critical"},
                                        "event_type": "Log Tampering",
                                        "message": "CRITICAL: Security logs were cleared! TAMPER detected.",
                                        "user": "System_Admin",
                                        "packet_size": 0,
                                        "flow_duration": 0,
                                        "requests_sec": 0,
                                    }
                                ]
                            )
                win32evtlog.CloseEventLog(hand)
                time.sleep(3)
            except Exception as e:
                if "Access is denied" in str(e):
                    print("[!] ERROR: Windows Logs require Administrator privileges.")
                time.sleep(10)


# --- FIREWALL SETUP ---

def sync_firewall_with_cloud():
    return _defense.sync_firewall_with_cloud()

# --- SIGNATURE CONFIG ---
MALICIOUS_SIGNATURES = ["NMAP", "ZGRAB", "MASSCAN", "CENSYS", "GOPHER"]

# --- NOTIFICATION ---
# --- ADD THIS TO SNIFFER.PY ---
NTFY_TOPIC = "siem_alerts_Hussain"

# --- Module-level singletons (wiring) ---
_threat_intel = ThreatIntel(intel_url=INTEL_URL, debug=DEBUG_MODE)
_geo = GeoEnrichment(siem_ip=SIEM_IP, threat_intel=_threat_intel)
_defense = ActiveDefense(blocked_ips_url=BLOCKED_IPS_URL)
_network_agent = NetworkAgent(
    api_url=API_URL,
    geo=_geo,
    dos_threshold=DOS_THRESHOLD,
    scan_threshold=SCAN_THRESHOLD,
    honeypot_ports=HONEYPOT_PORTS,
)
_windows_agent = WindowsAgent(send_to_siem=_network_agent.send_to_siem)
_mobile_push = MobilePushAlerts(topic=NTFY_TOPIC)

def push_to_mobile(alert_type, ip, message):
    return _mobile_push.push_to_mobile(alert_type, ip, message)

def get_geo_location(ip):
    return _geo.get_geo_location(ip)

def sync_threat_intel():
    return _threat_intel.sync_loop()

def send_to_siem(data):
    return _network_agent.send_to_siem(data)

def process_packet(pkt):
    return _network_agent.process_packet(pkt)

def fetch_windows_logs():
    return _windows_agent.fetch_windows_logs()


def start_sniffing():
    return _network_agent.start_sniffing()

def run_firewall_sync():
    return _defense.run_firewall_sync()

if __name__ == "__main__":
    # 1. Start existing intelligence and log sensors
    threading.Thread(target=_threat_intel.sync_loop, daemon=True).start()
    threading.Thread(target=_windows_agent.fetch_windows_logs, daemon=True).start()
    
    # 2. Start the new Firewall Sync sensor
    threading.Thread(target=_defense.run_firewall_sync, daemon=True).start()
    
    # 3. Start the main Sniffer (DPI/Honeypot)
    # We keep this as a thread or foreground process
    threading.Thread(target=_network_agent.start_sniffing, daemon=True).start()

    print("🛡️  SIEM SENSORS ONLINE: DPI + Windows + Honeypot + Port Scan + Geo-IP + Firewall Sync.")
    
    # Keep the main thread alive
    while True: 
        _defense.sync_firewall_with_cloud()
        time.sleep(1)