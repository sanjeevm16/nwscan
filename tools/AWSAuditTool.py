import json
import os
from datetime import datetime
from .ec2_collector import collect_ec2_network_health
from .eni_collector import collect_eni_health
from .elb_collector import collect_elb_health
from .utils.aws_session import get_client

AWS_BASELINE_FILE = "aws_baseline.json"

def load_aws_baseline() -> dict:
    if os.path.exists(AWS_BASELINE_FILE):
        with open(AWS_BASELINE_FILE, "r") as f:
            return json.load(f)
    return {}

def save_aws_baseline(data: dict) -> None:
    with open(AWS_BASELINE_FILE, "w") as f:
        json.dump(data, f, indent=4)

def collect_all_aws_metrics():
    # In a real scenario, we'd discover these IDs. For now, using placeholders or common ones.
    # This is a simplified version for the demo UI.
    try:
        metrics = {
            "ec2": collect_ec2_network_health("i-0123456789abcdef0"),
            "eni": collect_eni_health("eni-0123456789abcdef0"),
            "elb": collect_elb_health("my-load-balancer")
        }
        return metrics
    except Exception as e:
        return {"error": str(e)}

def audit_aws_drift(region="us-west-2", role_arn=None, external_id=None):
    baseline = load_aws_baseline()
    if not baseline:
        return {"status": "info", "message": "No AWS baseline found. Update baseline first."}

    try:
        ec2 = get_client("ec2", region=region, role_arn=role_arn, external_id=external_id)
        sgs = ec2.describe_security_groups()["SecurityGroups"]
        
        current_state = {sg["GroupId"]: sg for sg in sgs}
        
        drift = {
            "new_sgs": [],
            "deleted_sgs": [],
            "modified_sgs": []
        }
        
        for sg_id, sg in current_state.items():
            if sg_id not in baseline:
                drift["new_sgs"].append(sg_id)
            else:
                # Simple comparison of IpPermissions
                if baseline[sg_id]["IpPermissions"] != sg["IpPermissions"]:
                    drift["modified_sgs"].append(sg_id)
                    
        for sg_id in baseline:
            if sg_id not in current_state:
                drift["deleted_sgs"].append(sg_id)
        
        has_drift = any(drift[k] for k in drift)
        return {
            "status": "warning" if has_drift else "success",
            "drift": drift,
            "message": "Drift detected" if has_drift else "No drift detected"
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

def update_aws_baseline(region="us-west-2", role_arn=None, external_id=None):
    try:
        ec2 = get_client("ec2", region=region, role_arn=role_arn, external_id=external_id)
        sgs = ec2.describe_security_groups()["SecurityGroups"]
        baseline = {sg["GroupId"]: sg for sg in sgs}
        save_aws_baseline(baseline)
        return {"status": "success", "message": f"Baseline updated with {len(baseline)} security groups."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def detect_aws_vulnerabilities(region="us-west-2", role_arn=None, external_id=None):
    findings = []
    try:
        ec2 = get_client("ec2", region=region, role_arn=role_arn, external_id=external_id)
        sgs = ec2.describe_security_groups()["SecurityGroups"]
        
        for sg in sgs:
            for perm in sg.get("IpPermissions", []):
                for range in perm.get("IpRanges", []):
                    if range.get("CidrIp") == "0.0.0.0/0":
                        port = perm.get("FromPort")
                        if port in [22, 3389, 80, 443, 21, 23]:
                            findings.append({
                                "resource": sg["GroupId"],
                                "type": "SecurityGroup",
                                "issue": f"Open port {port} to the world",
                                "severity": "HIGH" if port in [22, 3389] else "MEDIUM"
                            })
        
        # Check for unencrypted volumes
        volumes = ec2.describe_volumes()["Volumes"]
        for vol in volumes:
            if not vol.get("Encrypted"):
                findings.append({
                    "resource": vol["VolumeId"],
                    "type": "EBSVolume",
                    "issue": "Volume is not encrypted",
                    "severity": "LOW"
                })
                
        return {
            "status": "success",
            "findings": findings,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}
