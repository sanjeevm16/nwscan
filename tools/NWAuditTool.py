import os
import json
import nmap
from datetime import datetime

format_str = "%Y%m%d-%H%M%S"

# Path to store the approved network configuration baseline
BASELINE_FILE = "network_baseline.json"

# Default target subnet (can be overridden by callers)
DEFAULT_TARGET = "172.17.0.1/24"

# Check if we should use --privileged for nmap (required when using capabilities as non-root)
NMAP_PRIVILEGED = "--privileged " if os.getuid() != 0 else ""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_baseline() -> dict:
    """Loads the approved network baseline from a JSON file."""
    if os.path.exists(BASELINE_FILE):
        with open(BASELINE_FILE, "r") as f:
            return json.load(f)
    return {}


def save_baseline(data: dict) -> None:
    """Saves the approved network baseline to a JSON file."""
    with open(BASELINE_FILE, "w") as f:
        json.dump(data, f, indent=4)


# ---------------------------------------------------------------------------
# Core scan (with configurable target)
# ---------------------------------------------------------------------------

def scan_network(target: str = DEFAULT_TARGET) -> dict:
    """Performs a lightweight ping and port scan of *target* (IP, CIDR range,
    or nmap-style range such as ``192.168.1.1-50``).

    Returns a dictionary keyed by IP address with device info including
    MAC address, vendor, hostname and open TCP ports.
    """
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments=f"{NMAP_PRIVILEGED}-F -sV -T4")

    current_state = {}
    for host in nm.all_hosts():
        if nm[host].state() == "up":
            addresses = nm[host].get("addresses", {})
            mac = addresses.get("mac", "UNKNOWN_MAC")
            vendor = nm[host].get("vendor", {}).get(mac, "Unknown Vendor")

            open_ports = []
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                open_ports.extend(list(ports))

            current_state[host] = {
                "mac": mac,
                "vendor": vendor,
                "open_ports": sorted(open_ports),
                "hostname": nm[host].hostname() or host,
            }

    return current_state


# ---------------------------------------------------------------------------
# Drift / Audit
# ---------------------------------------------------------------------------

def audit_network(target: str = DEFAULT_TARGET) -> str:
    """Scans *target*, compares it against the saved baseline, and detects
    configuration drift or new/missing devices.

    Returns a human-readable string summary or a JSON drift report.
    """
    baseline = load_baseline()
    if not baseline:
        return (
            "⚠️ No baseline found. "
            "Please run 'update_baseline' first to lock down the current state."
        )

    try:
        current_state = scan_network(target)
    except Exception as e:
        return (
            f"❌ Network scan failed: {str(e)}. "
            "Ensure Nmap is installed and running with proper permissions."
        )

    drift_report = {
        "new_devices_detected": {},
        "missing_devices": {},
        "port_changes_detected": {},
    }

    for ip, info in current_state.items():
        if ip not in baseline:
            drift_report["new_devices_detected"][ip] = info
        else:
            baseline_ports = set(baseline[ip]["open_ports"])
            current_ports = set(info["open_ports"])
            if baseline_ports != current_ports:
                drift_report["port_changes_detected"][ip] = {
                    "mac": info["mac"],
                    "vendor": info.get("vendor", "Unknown"),
                    "expected_ports": sorted(baseline_ports),
                    "found_ports": sorted(current_ports),
                    "added_ports": sorted(current_ports - baseline_ports),
                    "closed_ports": sorted(baseline_ports - current_ports),
                }

    for ip, info in baseline.items():
        if ip not in current_state:
            drift_report["missing_devices"][ip] = info

    has_drift = any(drift_report[k] for k in drift_report)
    if not has_drift:
        return (
            "✅ Network Audit Complete: No drift detected. "
            "All devices match the approved baseline."
        )

    return json.dumps(
        {"status": "⚠️ DRIFT DETECTED", "report": drift_report}, indent=2
    )


def update_baseline(target: str = DEFAULT_TARGET) -> str:
    """Scans *target* and saves the current live state as the new approved
    baseline configuration.

    Returns a human-readable confirmation or error message.
    """
    try:
        current_state = scan_network(target)
        save_baseline(current_state)
        return (
            f"🚀 Baseline updated successfully! "
            f"{len(current_state)} devices registered as approved network state."
        )
    except Exception as e:
        return f"❌ Failed to update baseline: {str(e)}"


# ---------------------------------------------------------------------------
# Vulnerability: UDP Port Anomaly Detection
# ---------------------------------------------------------------------------

# Well-known UDP services that are rarely legitimate on end-user hosts
_SUSPICIOUS_UDP_PORTS = {
    69:   "TFTP — unauthenticated file transfer, often abused for firmware flashing or exfil",
    161:  "SNMP — community-string auth; exposes full device configuration",
    162:  "SNMP Trap — may receive unsolicited management frames",
    500:  "IKE/ISAKMP — VPN negotiation; misconfigured endpoints are exploitable",
    1900: "UPnP — frequently exploited for reflection DDoS and LAN traversal",
    5353: "mDNS — information leakage about hostnames and services",
    17185:"VxWorks WDBRPC — critical RCE on embedded/industrial devices",
    11211:"Memcached — open Memcached UDP amplifies DDoS 51 000×",
    623:  "IPMI — BMC management; default credentials widely known",
    137:  "NetBIOS NS — name-service enumeration and NBNS spoofing",
    138:  "NetBIOS DGM — datagram leakage, relay attack surface",
}


def detect_udp_anomalies(target: str = DEFAULT_TARGET) -> dict:
    """Scans *target* for open UDP ports and flags well-known dangerous services.

    Returns a structured report with findings and a remediation plan per host.
    """
    nm = nmap.PortScanner()
    # -sU: UDP scan  -p: only the interesting ports  --open: show open/open|filtered only
    ports_arg = ",".join(str(p) for p in _SUSPICIOUS_UDP_PORTS)
    nm.scan(
        hosts=target,
        arguments=f"{NMAP_PRIVILEGED}-sU -p {ports_arg} --open -T4 --max-retries 2",
    )

    findings: dict = {}
    for host in nm.all_hosts():
        if "udp" not in nm[host].all_protocols():
            continue
        host_findings = []
        for port, state_info in nm[host]["udp"].items():
            state = state_info.get("state", "")
            if state in ("open", "open|filtered") and port in _SUSPICIOUS_UDP_PORTS:
                risk = _classify_udp_risk(port)
                host_findings.append({
                    "port": port,
                    "state": state,
                    "service": state_info.get("name", "unknown"),
                    "risk": risk,
                    "description": _SUSPICIOUS_UDP_PORTS[port],
                    "remediation": _udp_remediation(port),
                })

        if host_findings:
            findings[host] = {
                "hostname": nm[host].hostname() or host,
                "vulnerabilities": host_findings,
                "overall_risk": max(f["risk"] for f in host_findings),
            }

    summary = {
        "scan_type": "UDP Port Anomaly Detection",
        "target": target,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "hosts_with_findings": len(findings),
        "findings": findings,
        "remediation_plan": _udp_global_plan(findings),
    }
    return summary


def _classify_udp_risk(port: int) -> str:
    critical = {17185, 11211, 623, 69}
    high = {161, 162, 500, 1900}
    if port in critical:
        return "CRITICAL"
    if port in high:
        return "HIGH"
    return "MEDIUM"


def _udp_remediation(port: int) -> list[str]:
    plans = {
        69:   ["Disable tftpd daemon immediately",
               "Block UDP/69 inbound+outbound at perimeter firewall",
               "Use SFTP/SCP for legitimate file transfers"],
        161:  ["Disable SNMPv1/v2c; migrate to SNMPv3 with auth+encryption",
               "Restrict SNMP access to a dedicated management VLAN",
               "Rotate/change all community strings; never use 'public'/'private'"],
        162:  ["Accept SNMP traps only from authorised NMS addresses",
               "Use SNMPv3 inform-requests instead of unauthenticated traps"],
        500:  ["Patch IKE daemon to latest version",
               "Enforce IKEv2 only; disable aggressive mode",
               "Restrict UDP/500 to known VPN peer IPs via ACL"],
        1900: ["Disable UPnP on all routers and IoT devices",
               "Block UDP/1900 at the perimeter",
               "Audit devices for UPnP IGD exposure (use upnp-inspector)"],
        5353: ["Isolate mDNS to its subnet; block at inter-VLAN firewall",
               "Use unicast DNS for cross-subnet resolution",
               "Consider mDNS gateway/proxy to limit scope"],
        17185:["Immediately isolate affected device (critical RCE)",
               "Apply vendor firmware patch or disable WDBRPC service",
               "Segregate embedded/industrial devices behind a dedicated firewall"],
        11211:["Bind Memcached to 127.0.0.1 only",
               "Enable SASL authentication",
               "Block UDP/11211 at perimeter; consider disabling UDP transport"],
        623:  ["Disable IPMI/BMC if not required",
               "Change default credentials immediately",
               "Restrict UDP/623 to a dedicated out-of-band management network"],
        137:  ["Disable NetBIOS over TCP/IP on all interfaces",
               "Block ports 137-139 at perimeter and between VLANs",
               "Migrate name resolution to DNS"],
        138:  ["Disable NetBIOS Datagram service",
               "Enforce SMB signing to prevent relay attacks"],
    }
    return plans.get(port, ["Investigate service necessity", "Block at firewall if not required"])


def _udp_global_plan(findings: dict) -> list[str]:
    if not findings:
        return ["No suspicious UDP services detected. Maintain regular UDP sweeps."]
    plan = [
        "1. Immediately isolate any CRITICAL-risk hosts from the production network.",
        "2. Disable or patch all flagged UDP services within 24 h for CRITICAL, 72 h for HIGH.",
        "3. Implement egress + ingress firewall rules blocking dangerous UDP ports at the perimeter.",
        "4. Deploy network IDS rules (Suricata/Snort) to alert on traffic to/from flagged ports.",
        "5. Schedule monthly UDP sweep scans and integrate into CI/CD security pipeline.",
        "6. Maintain an approved-service whitelist; block all unlisted UDP services by default.",
    ]
    return plan


# ---------------------------------------------------------------------------
# Vulnerability: OS Fingerprinting
# ---------------------------------------------------------------------------

_EOL_OS_PATTERNS = [
    ("Windows XP",        "CRITICAL — no patches since 2014; full exploit chain exposure"),
    ("Windows 7",         "HIGH — EOL Jan 2020; exposed to EternalBlue and later exploits"),
    ("Windows Server 2003","CRITICAL — EOL Jul 2015"),
    ("Windows Server 2008","HIGH — EOL Jan 2020"),
    ("CentOS 6",          "HIGH — EOL Nov 2020"),
    ("CentOS 7",          "MEDIUM — EOL Jun 2024"),
    ("Ubuntu 16",         "MEDIUM — EOL Apr 2021"),
    ("Ubuntu 18",         "MEDIUM — EOL Jun 2023"),
    ("Debian 9",          "MEDIUM — EOL Jun 2022"),
    ("Android 9",         "HIGH — no security updates from Google"),
]


def detect_os_fingerprinting(target: str = DEFAULT_TARGET) -> dict:
    """Uses nmap OS detection (-O) to fingerprint operating systems of all
    live hosts in *target* and flags end-of-life or otherwise risky OSes.

    Returns a structured report with OS findings and a remediation plan.

    .. note::
        Requires root/administrator privileges for raw-socket OS detection.
    """
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments=f"{NMAP_PRIVILEGED}-O -T4 --osscan-guess")

    findings: dict = {}
    for host in nm.all_hosts():
        if nm[host].state() != "up":
            continue

        os_matches = nm[host].get("osmatch", [])
        if not os_matches:
            continue

        best = os_matches[0]
        os_name = best.get("name", "Unknown")
        accuracy = int(best.get("accuracy", 0))
        os_classes = best.get("osclass", [{}])
        os_family = os_classes[0].get("osfamily", "Unknown") if os_classes else "Unknown"
        os_gen = os_classes[0].get("osgen", "") if os_classes else ""

        eol_info = _check_os_eol(os_name)
        risk = eol_info["risk"] if eol_info else _os_risk_from_family(os_family, os_gen)

        findings[host] = {
            "hostname": nm[host].hostname() or host,
            "os_name": os_name,
            "os_family": os_family,
            "os_generation": os_gen,
            "accuracy_pct": accuracy,
            "risk": risk,
            "eol": eol_info is not None,
            "eol_details": eol_info.get("detail", "") if eol_info else "",
            "all_matches": [
                {"name": m.get("name"), "accuracy": m.get("accuracy")}
                for m in os_matches[:3]
            ],
            "remediation": _os_remediation(os_name, os_family, eol_info),
        }

    summary = {
        "scan_type": "OS Fingerprinting",
        "target": target,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "hosts_scanned": len([h for h in nm.all_hosts() if nm[h].state() == "up"]),
        "hosts_with_findings": len(findings),
        "findings": findings,
        "remediation_plan": _os_global_plan(findings),
    }
    return summary


def _check_os_eol(os_name: str) -> dict | None:
    for pattern, detail in _EOL_OS_PATTERNS:
        if pattern.lower() in os_name.lower():
            risk = "CRITICAL" if "CRITICAL" in detail else "HIGH" if "HIGH" in detail else "MEDIUM"
            return {"detail": detail, "risk": risk}
    return None


def _os_risk_from_family(family: str, gen: str) -> str:
    if family in ("embedded", "specialized"):
        return "HIGH"
    return "LOW"


def _os_remediation(os_name: str, os_family: str, eol_info: dict | None) -> list[str]:
    steps = []
    if eol_info:
        steps.append(f"⚠️ EOL OS detected: {eol_info['detail']}")
        steps.append("Immediately plan OS upgrade or replacement of the host.")
        steps.append("Apply vendor-provided Extended Security Updates (ESU) as short-term mitigation.")
    steps += [
        "Ensure automatic security patching is enabled.",
        "Run a vulnerability scanner (OpenVAS/Nessus) specifically against this host.",
        "Enable host-based firewall and disable unnecessary services.",
        "Segment the host into a dedicated VLAN if it cannot be immediately upgraded.",
        "Implement endpoint detection and response (EDR) on the host.",
    ]
    return steps


def _os_global_plan(findings: dict) -> list[str]:
    if not findings:
        return ["No risky OS versions detected. Maintain a patching schedule."]
    critical = [h for h, d in findings.items() if d["risk"] == "CRITICAL"]
    plan = [
        "1. Create an asset inventory of all detected OS versions.",
        "2. Immediately isolate CRITICAL-risk (EOL) hosts — network segmentation or shutdown.",
        "3. Establish an OS upgrade project with milestones within 30/60/90 days.",
        "4. Subscribe all systems to vendor security advisories (CVE feeds).",
        "5. Deploy an automated patch management tool (WSUS, Ansible, Puppet).",
        "6. Re-run OS fingerprint scans after each patching cycle.",
    ]
    if critical:
        plan.insert(1, f"   ⚡ {len(critical)} CRITICAL host(s) require immediate action: {', '.join(critical)}")
    return plan


# ---------------------------------------------------------------------------
# Vulnerability: Firewall & IDS Evasion Detection
# ---------------------------------------------------------------------------

def detect_firewall_ids_evasion(target: str = DEFAULT_TARGET) -> dict:
    """Probes *target* using multiple nmap techniques that simulate common
    firewall/IDS evasion tactics and reports which hosts appear vulnerable
    to packet-filter bypasses or IDS blind spots.

    Techniques tested
    -----------------
    * SYN scan baseline (standard traffic behaviour)
    * FIN/NULL/Xmas scans (bypass stateless packet filters)
    * Fragmented packets (elude shallow-inspection firewalls)
    * Decoy scan simulation (check whether host appears in decoy responses)
    * Source-port spoofing to common trusted ports (53, 80, 443)

    Returns a structured report with evasion findings and hardening plan.
    """
    nm = nmap.PortScanner()
    findings: dict = {}

    # -- Technique 1: SYN baseline ----------------------------------------
    nm.scan(hosts=target, arguments=f"{NMAP_PRIVILEGED}-sS -p 22,80,443,3389,8080 -T4")
    syn_open: dict[str, set] = {}
    for host in nm.all_hosts():
        if nm[host].state() != "up":
            continue
        open_p: set = set()
        if "tcp" in nm[host].all_protocols():
            open_p = {p for p, s in nm[host]["tcp"].items() if s["state"] == "open"}
        syn_open[host] = open_p

    # -- Technique 2: FIN scan (bypasses stateless ACLs) ------------------
    nm2 = nmap.PortScanner()
    nm2.scan(hosts=target, arguments=f"{NMAP_PRIVILEGED}-sF -p 22,80,443,3389,8080 -T4")
    fin_open: dict[str, set] = {}
    for host in nm2.all_hosts():
        if nm2[host].state() != "up":
            continue
        open_p = set()
        if "tcp" in nm2[host].all_protocols():
            open_p = {p for p, s in nm2[host]["tcp"].items()
                      if s["state"] in ("open", "open|filtered")}
        fin_open[host] = open_p

    # -- Technique 3: Fragmented packet scan ------------------------------
    nm3 = nmap.PortScanner()
    nm3.scan(hosts=target, arguments=f"{NMAP_PRIVILEGED}-sS -f -p 22,80,443,3389,8080 -T4")
    frag_open: dict[str, set] = {}
    for host in nm3.all_hosts():
        if nm3[host].state() != "up":
            continue
        open_p = set()
        if "tcp" in nm3[host].all_protocols():
            open_p = {p for p, s in nm3[host]["tcp"].items() if s["state"] == "open"}
        frag_open[host] = open_p

    # -- Technique 4: Source-port spoofing --------------------------------
    nm4 = nmap.PortScanner()
    nm4.scan(hosts=target, arguments=f"{NMAP_PRIVILEGED}-sS --source-port 53 -p 22,80,443,3389,8080 -T4")
    srcport_open: dict[str, set] = {}
    for host in nm4.all_hosts():
        if nm4[host].state() != "up":
            continue
        open_p = set()
        if "tcp" in nm4[host].all_protocols():
            open_p = {p for p, s in nm4[host]["tcp"].items() if s["state"] == "open"}
        srcport_open[host] = open_p

    # -- Consolidate findings ---------------------------------------------
    all_hosts = set(syn_open) | set(fin_open) | set(frag_open) | set(srcport_open)
    for host in all_hosts:
        issues = []
        syn = syn_open.get(host, set())
        fin = fin_open.get(host, set())
        frag = frag_open.get(host, set())
        src = srcport_open.get(host, set())

        # Ports visible via FIN but not SYN → stateless filter bypass
        fin_bypass = fin - syn
        if fin_bypass:
            issues.append({
                "technique": "FIN Scan Bypass",
                "severity": "HIGH",
                "ports_exposed": sorted(fin_bypass),
                "description": (
                    "Ports respond to FIN probes that are blocked in SYN scan. "
                    "Indicates a stateless packet filter (ACL) rather than stateful "
                    "firewall. An attacker can enumerate and connect to these ports."
                ),
            })

        # Ports visible via fragmented packets not seen in SYN → shallow inspection
        frag_bypass = frag - syn
        if frag_bypass:
            issues.append({
                "technique": "Fragmented Packet Bypass",
                "severity": "HIGH",
                "ports_exposed": sorted(frag_bypass),
                "description": (
                    "Fragmented packets bypass the firewall filter, exposing ports "
                    "that a normal scan does not reveal. The firewall does not reassemble "
                    "fragments before inspection."
                ),
            })

        # Ports visible via spoofed source-port 53 → source-port trust rules
        src_bypass = src - syn
        if src_bypass:
            issues.append({
                "technique": "Source-Port Spoofing Bypass",
                "severity": "CRITICAL",
                "ports_exposed": sorted(src_bypass),
                "description": (
                    "The firewall trusts traffic originating from port 53 (DNS). "
                    "Spoofing source port 53 bypasses the filter. An attacker can reach "
                    "otherwise-blocked services by using a DNS source port."
                ),
            })

        # Ports universally open (SYN + all other techniques) → no evasion needed
        universally_open = syn & fin & frag & src
        if universally_open:
            issues.append({
                "technique": "Universal Access (No Evasion Required)",
                "severity": "INFO",
                "ports_exposed": sorted(universally_open),
                "description": (
                    "These ports are reachable via all scan methods. "
                    "Ensure only intentionally public services are listed here."
                ),
            })

        if issues:
            risk_levels = [i["severity"] for i in issues if i["severity"] != "INFO"]
            overall = "CRITICAL" if "CRITICAL" in risk_levels else (
                "HIGH" if "HIGH" in risk_levels else "MEDIUM"
            )
            hostname = nm.all_hosts() and nm[host].hostname() if host in nm.all_hosts() else host
            findings[host] = {
                "hostname": hostname or host,
                "issues": issues,
                "overall_risk": overall,
                "remediation": _firewall_host_remediation(issues),
            }

    summary = {
        "scan_type": "Firewall & IDS Evasion Detection",
        "target": target,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "techniques_used": [
            "SYN Scan (baseline)",
            "FIN Scan (stateless filter bypass)",
            "Fragmented Packet Scan",
            "Source-Port Spoofing (DNS port 53)",
        ],
        "hosts_with_findings": len(findings),
        "findings": findings,
        "remediation_plan": _firewall_global_plan(findings),
    }
    return summary


def _firewall_host_remediation(issues: list) -> list[str]:
    steps = []
    techniques = {i["technique"] for i in issues}
    if "FIN Scan Bypass" in techniques:
        steps += [
            "Replace stateless ACLs with a stateful firewall (iptables conntrack, pf, or NGFW).",
            "Enable TCP state tracking to reject FIN/RST packets without prior SYN.",
        ]
    if "Fragmented Packet Bypass" in techniques:
        steps += [
            "Enable IP fragment reassembly on the firewall before rule evaluation.",
            "Set 'ip_always_defrag 1' in iptables/nftables or equivalent on NGFW.",
            "Configure minimum fragment size enforcement to drop tiny fragments.",
        ]
    if "Source-Port Spoofing Bypass" in techniques:
        steps += [
            "Remove or audit any firewall rules that allow traffic based solely on source port.",
            "Use application-aware (Layer-7) inspection rather than port-based trust.",
            "Deploy an IDS (Suricata) to alert on unexpected source-port usage patterns.",
        ]
    steps += [
        "Perform regular firewall rule audits and remove stale/permissive rules.",
        "Deploy a Next-Generation Firewall with deep-packet inspection.",
        "Enable IDS/IPS signatures for scan evasion patterns (Snort SID 1228, etc.).",
    ]
    return steps


def _firewall_global_plan(findings: dict) -> list[str]:
    if not findings:
        return [
            "No evasion vulnerabilities detected with current techniques.",
            "Continue to test with updated evasion toolkits quarterly.",
        ]
    return [
        "1. Upgrade all stateless ACLs to stateful firewalls with connection tracking.",
        "2. Enable full IP fragment reassembly at the perimeter firewall.",
        "3. Audit and remove source-port-based trust rules across all firewall policies.",
        "4. Deploy Suricata/Snort IDS with evasion detection ruleset (ET-OPEN or Talos).",
        "5. Implement network traffic baselining to detect scan anomalies (Zeek/Arkime).",
        "6. Schedule quarterly red-team exercises simulating evasion techniques.",
        "7. Review and harden NGFW policies with a least-privilege/default-deny posture.",
    ]
