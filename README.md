# NetSentinel — Network Audit & Drift Detector

NetSentinel is a comprehensive network security auditing tool designed to provide real-time visibility into network configurations, detect unauthorized changes (drift), and identify common vulnerabilities. It combines a powerful Nmap-based backend with a modern web dashboard and supports the **Model Context Protocol (MCP)** for seamless integration with AI agents.

## 🚀 Features

- **Network Scanning:** Fast discovery of active hosts, MAC addresses, vendors, and open TCP ports.
- **Baseline & Drift Detection:** Lock down an approved network state and receive instant alerts when new devices appear, existing ones go missing, or port configurations change.
- **UDP Anomaly Detection:** Scans for dangerous UDP services (TFTP, SNMP, UPnP, Memcached, IPMI) and provides detailed remediation plans.
- **OS Fingerprinting:** Identifies host operating systems and flags End-of-Life (EOL) systems that lack security patches.
- **Firewall & IDS Evasion Testing:** Simulates advanced evasion techniques (FIN/NULL/Xmas scans, fragmented packets, source-port spoofing) to find blind spots in your network security.
- **MCP Integration:** Fully compatible with MCP, allowing LLMs to autonomously perform audits and vulnerability assessments.
- **Interactive Dashboard:** A beautiful, responsive web UI for managing scans and viewing reports.

---

## 🏗️ Runtime Architecture

NetSentinel is built on a modular architecture that bridges low-level network probing with high-level AI orchestration and web visualization.

### Architecture Overview

1.  **System Layer (Nmap):** The core engine uses the industrial-standard nmap utility. It must be installed on the host system.
2.  **Logic Layer (NWAuditTool.py):** A Python wrapper around nmap that implements specific security logic, risk classification, and baseline comparison.
3.  **Server Layer (network_audit_server.py):**
    -   **FastAPI:** Provides a RESTful API for the web dashboard.
    -   **FastMCP:** Implements the Model Context Protocol, exposing the tools to AI clients.
    -   **Static Hosting:** Serves the frontend dashboard.
4.  **Data Layer (network_baseline.json):** Stores the approved state of the network in a portable JSON format.
5.  **Presentation Layer (ui/index.html):** A single-page application (SPA) that communicates with the REST API.

---

## 🛠️ Prerequisites

- **Python 3.10+**
- **Nmap:** Must be installed and available in your system's PATH.
- **Root/Admin Privileges:** Required for advanced scans like OS fingerprinting and firewall evasion.

### Installing Nmap
- **Linux:** sudo apt install nmap
- **macOS:** brew install nmap
- **Windows:** Download from nmap.org

---

## 📦 Installation

1. **Clone the repository:**
   \`\`\`bash
   git clone <repository-url>
   cd nwscan
   \`\`\`

2. **Install dependencies:**
   \`\`\`bash
   pip install fastapi uvicorn python-nmap mcp pydantic
   \`\`\`

---

## 🚦 Usage

### 1. Start the Server
Run the following command to start both the REST API and the web UI:
\`\`\`bash
python network_audit_server.py
\`\`\`
The server will start on http://0.0.0.0:8000.

### 2. Access the Dashboard
Open your browser and navigate to:
http://localhost:8000/ui

### 3. Use via MCP
If you are using an MCP-compatible client (like Gemini CLI or Claude Desktop), add this server to your configuration:
\`\`\`json
{
  "mcpServers": {
    "netsentinel": {
      "command": "python",
      "args": ["/path/to/nwscan/network_audit_server.py"]
    }
  }
}
\`\`\`

---

## 📁 Project Structure

- network_audit_server.py: Main entry point (FastAPI + MCP).
- tools/NWAuditTool.py: Core logic for scanning, auditing, and vulnerability detection.
- ui/index.html: Web dashboard frontend.
- network_baseline.json: Stores the approved network state.
- .env: Environment configuration.

---

## ⚠️ Security Warning

NetSentinel performs network probing which may be flagged by Intrusion Detection Systems (IDS). Ensure you have explicit authorization to scan the target networks. Advanced scans (OS detection, etc.) require elevated privileges (sudo).

---

## 🛡️ Security Hardening & Elevated Permissions

Advanced features like OS Fingerprinting and Firewall Evasion require `nmap` to have raw socket access. Running the entire application as `root` is **not recommended** as it increases the attack surface of the web server.

### Recommended Approach: Linux Capabilities (Least Privilege)
The most secure way to enable these features is to grant specific network capabilities to the `nmap` binary. This allows it to perform privileged operations while the Python application runs as a normal user.

Run these commands on your host system:
```bash
# Grant Nmap the ability to use raw sockets and admin net tasks
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)

# Verify the capabilities
getcap $(which nmap)
```

### Alternative: Restricted Sudoers
If you cannot use capabilities, restrict `sudo` access to *only* the nmap binary for the specific user running the server:
1. Run `sudo visudo`.
2. Add the following line:
   `youruser ALL=(root) NOPASSWD: /usr/bin/nmap`

### Long-Term Architectural Strategy: Privilege Separation
For maximum security in production environments, NetSentinel follows a "Privilege Separation" philosophy:
- **Web/API Tier:** Unprivileged process handling requests and UI.
- **Scanning Tier:** A minimal, hardened worker process or sidecar with elevated capabilities that only executes validated `nmap` commands.

---

## 📄 License

MIT
