import pytest
from fastapi.testclient import TestClient
from network_audit_server import app
from unittest.mock import patch, MagicMock

client = TestClient(app)

@patch("tools.AWSAuditTool.get_client")
@patch("tools.AWSAuditTool.load_aws_baseline")
def test_aws_audit_with_arn(mock_load_baseline, mock_get_client):
    # Setup mocks
    mock_load_baseline.return_value = {"sg-123": {"IpPermissions": []}}
    mock_ec2 = MagicMock()
    mock_ec2.describe_security_groups.return_value = {
        "SecurityGroups": [{"GroupId": "sg-123", "IpPermissions": []}]
    }
    mock_get_client.return_value = mock_ec2

    # Request with ARN and other cloud configs
    payload = {
        "region": "us-east-1",
        "role_arn": "arn:aws:iam::123456789012:role/AuditRole",
        "external_id": "test-external-id",
        "resource_arn": "arn:aws:ec2:us-east-1:123456789012:vpc/vpc-123"
    }
    
    response = client.post("/aws/audit", json=payload)
    
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "drift" in data["data"]
    
    # Verify mock was called with correct parameters
    mock_get_client.assert_called_once_with(
        "ec2", 
        region="us-east-1", 
        role_arn="arn:aws:iam::123456789012:role/AuditRole",
        external_id="test-external-id"
    )

@patch("tools.pqc_observability.orchestrator.collect_pqc_posture")
def test_pqc_collect_with_resource(mock_collect):
    # Setup mock
    mock_collect.return_value = {
        "algorithms": {"kyber512": {"avg_time_ms": 1.2}},
        "summary": {"pqc_ready": True}
    }

    # Request with environment and resource ARN
    payload = {
        "env": "aws-vpc",
        "resource_arn": "arn:aws:lambda:us-west-2:123456789012:function:my-func"
    }
    
    response = client.post("/pqc/collect", json=payload)
    
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["data"]["environment"] == "aws-vpc"
    assert "algorithms" in data["data"]

@patch("tools.AWSAuditTool.get_client")
def test_aws_vuln_with_configs(mock_get_client):
    # Setup mocks
    mock_ec2 = MagicMock()
    mock_ec2.describe_security_groups.return_value = {"SecurityGroups": []}
    mock_ec2.describe_volumes.return_value = {"Volumes": []}
    mock_get_client.return_value = mock_ec2

    payload = {
        "region": "eu-central-1",
        "role_arn": "arn:aws:iam::999999999999:role/SecurityScanner"
    }
    
    response = client.post("/aws/vuln", json=payload)
    
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "findings" in data["data"]
    
    mock_get_client.assert_called_once_with(
        "ec2", 
        region="eu-central-1", 
        role_arn="arn:aws:iam::999999999999:role/SecurityScanner",
        external_id=None
    )

@patch("network_audit_server.audit_aws_drift")
def test_mcp_audit_aws_drift(mock_audit):
    from network_audit_server import mcp_audit_aws_drift
    import json
    
    # Mocking
    mock_audit.return_value = {"status": "success", "drift": {}}
    
    # Call MCP tool directly
    result_json = mcp_audit_aws_drift(
        region="us-west-2", 
        role_arn="arn:aws:iam::111122223333:role/MCP-Role"
    )
    
    result = json.loads(result_json)
    assert result["status"] == "success"
    
    mock_audit.assert_called_once_with(
        "us-west-2",
        "arn:aws:iam::111122223333:role/MCP-Role",
        None
    )
