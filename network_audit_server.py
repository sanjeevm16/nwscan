import json
from tools.NWAuditTool import (
    audit_network,
    update_baseline,
    scan_network,
    load_baseline,
    detect_udp_anomalies,
    detect_os_fingerprinting,
    detect_firewall_ids_evasion,
)
from tools.AWSAuditTool import (
    collect_all_aws_metrics,
    audit_aws_drift,
    update_aws_baseline,
    detect_aws_vulnerabilities,
)
from tools.pqc_observability.orchestrator import run_pqc_telemetry
from mcp.server.fastmcp import FastMCP
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import uvicorn

# ---------------------------------------------------------------------------
# Request body schema
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    target: str = "172.17.0.1/24"

class AWSRequest(BaseModel):
    region: str = "us-west-2"
    role_arn: str = None
    external_id: str = None
    resource_arn: str = None

class PQCRequest(BaseModel):
    env: str = "on-prem"
    resource_arn: str = None



# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

mcp = FastMCP("Network-Audit-and-Drift-Detector")


@mcp.tool()
def mcp_scan_network(target: str = "172.17.0.1/24") -> str:
    """Performs a lightweight ping and port scan of the target subnet or IP range.
    Returns a JSON-formatted dictionary of discovered devices."""
    result = scan_network(target)
    return json.dumps(result, indent=2)


@mcp.tool()
def mcp_audit_network(target: str = "172.17.0.1/24") -> str:
    """Scans the target, compares it against the saved baseline, and
    reports any configuration drift or new/missing devices."""
    return audit_network(target)


@mcp.tool()
def mcp_update_baseline(target: str = "172.17.0.1/24") -> str:
    """Scans the target and saves the current live state as the new
    approved baseline configuration."""
    return update_baseline(target)


@mcp.tool()
def mcp_detect_udp_anomalies(target: str = "172.17.0.1/24") -> str:
    """Scans target for open dangerous UDP ports and returns a vulnerability
    report with risk classification and remediation plan."""
    result = detect_udp_anomalies(target)
    return json.dumps(result, indent=2)


@mcp.tool()
def mcp_detect_os_fingerprinting(target: str = "172.17.0.1/24") -> str:
    """Uses nmap OS detection to fingerprint operating systems of all live
    hosts in target and flags end-of-life or risky OSes."""
    result = detect_os_fingerprinting(target)
    return json.dumps(result, indent=2)


@mcp.tool()
def mcp_detect_firewall_ids_evasion(target: str = "172.17.0.1/24") -> str:
    """Probes target using multiple nmap evasion techniques and reports which
    hosts are vulnerable to firewall/IDS bypasses."""
    result = detect_firewall_ids_evasion(target)
    return json.dumps(result, indent=2)


@mcp.tool()
def mcp_collect_aws_metrics() -> str:
    """Collects network metrics from EC2, ENI, and ELB resources via CloudWatch."""
    result = collect_all_aws_metrics()
    return json.dumps(result, indent=2)


@mcp.tool()
def mcp_audit_aws_drift(region: str = "us-west-2", role_arn: str = None, external_id: str = None) -> str:
    """Detects configuration drift in AWS security groups by comparing current
    state against a saved baseline."""
    result = audit_aws_drift(region, role_arn, external_id)
    return json.dumps(result, indent=2)


@mcp.tool()
def mcp_update_aws_baseline(region: str = "us-west-2", role_arn: str = None, external_id: str = None) -> str:
    """Saves the current AWS security group configuration as the new approved baseline."""
    result = update_aws_baseline(region, role_arn, external_id)
    return json.dumps(result, indent=2)


@mcp.tool()
def mcp_detect_aws_vulnerabilities(region: str = "us-west-2", role_arn: str = None, external_id: str = None) -> str:
    """Scans AWS resources for common vulnerabilities like open security group
    ports and unencrypted EBS volumes."""
    result = detect_aws_vulnerabilities(region, role_arn, external_id)
    return json.dumps(result, indent=2)


@mcp.tool()
def mcp_run_pqc_telemetry(env: str = "on-prem", resource_arn: str = None) -> str:
    """Collects PQC performance metrics from the specified environment."""
    result = run_pqc_telemetry(env)
    # Note: resource_arn could be used here in the future
    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# FastAPI HTTP Server (used by the web UI)
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Network Audit API",
    description="REST API wrapper around the Network Audit MCP tools",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve the web UI from the /ui directory
app.mount("/ui", StaticFiles(directory="ui", html=True), name="ui")


@app.get("/", include_in_schema=False)
def root():
    return FileResponse("ui/index.html")


@app.get("/health")
def health():
    """Health check endpoint."""
    return {"status": "ok", "server": "Network-Audit-and-Drift-Detector"}


@app.get("/baseline")
def api_get_baseline():
    """Returns the currently saved baseline configuration."""
    baseline = load_baseline()
    return {"status": "success", "data": baseline, "count": len(baseline)}


@app.post("/scan")
def api_scan(req: ScanRequest):
    """Performs a live network scan and returns discovered devices."""
    try:
        result = scan_network(req.target)
        return {"status": "success", "data": result, "count": len(result)}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.post("/audit")
def api_audit(req: ScanRequest):
    """Runs a full network audit comparing live scan to the saved baseline."""
    try:
        result = audit_network(req.target)
        try:
            parsed = json.loads(result)
            return {"status": "success", "data": parsed, "raw": result}
        except json.JSONDecodeError:
            return {"status": "success", "data": None, "raw": result}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.post("/update-baseline")
def api_update_baseline(req: ScanRequest):
    """Saves the current live network state as the new approved baseline."""
    try:
        result = update_baseline(req.target)
        return {"status": "success", "message": result}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.post("/vuln/udp")
def api_vuln_udp(req: ScanRequest):
    """Scans for dangerous open UDP ports and returns anomaly report."""
    try:
        result = detect_udp_anomalies(req.target)
        return {"status": "success", "data": result}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.post("/vuln/os")
def api_vuln_os(req: ScanRequest):
    """Detects OS versions and flags end-of-life or risky operating systems."""
    try:
        result = detect_os_fingerprinting(req.target)
        return {"status": "success", "data": result}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.post("/vuln/firewall")
def api_vuln_firewall(req: ScanRequest):
    """Tests firewall/IDS evasion techniques and reports bypass vulnerabilities."""
    try:
        result = detect_firewall_ids_evasion(req.target)
        return {"status": "success", "data": result}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.get("/aws/metrics")
def api_aws_metrics():
    """Collects AWS network metrics."""
    try:
        result = collect_all_aws_metrics()
        return {"status": "success", "data": result}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.post("/aws/audit")
def api_aws_audit(req: AWSRequest):
    """Audits AWS security group configuration for drift."""
    try:
        result = audit_aws_drift(req.region, req.role_arn, req.external_id)
        return {"status": "success", "data": result}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.post("/aws/update-baseline")
def api_aws_update_baseline(req: AWSRequest):
    """Updates the AWS security group baseline."""
    try:
        result = update_aws_baseline(req.region, req.role_arn, req.external_id)
        return {"status": "success", "message": result}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.post("/aws/vuln")
def api_aws_vuln(req: AWSRequest):
    """Identifies common AWS vulnerabilities."""
    try:
        result = detect_aws_vulnerabilities(req.region, req.role_arn, req.external_id)
        return {"status": "success", "data": result}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.post("/pqc/collect")
def api_pqc_collect(req: PQCRequest):
    """Collects PQC performance metrics from a specified environment."""
    try:
        # In a real scenario, we might use req.resource_arn
        result = run_pqc_telemetry(req.env)
        return {"status": "success", "data": result}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ---------------------------------------------------------------------------
# Entry point — runs the HTTP server (use `python network_audit_server.py`)
# For MCP stdio mode, use: `mcp run network_audit_server.py`
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)
