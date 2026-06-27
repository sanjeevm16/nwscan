# utils/aws_session.py
import boto3

def get_session(region="us-west-2", role_arn=None, external_id=None):
    if role_arn:
        sts = boto3.client("sts", region_name=region)
        params = {
            "RoleArn": role_arn,
            "RoleSessionName": "NetSentinelAuditSession"
        }
        if external_id:
            params["ExternalId"] = external_id

        assumed_role = sts.assume_role(**params)
        credentials = assumed_role["Credentials"]
        return boto3.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name=region
        )
    return boto3.Session(region_name=region)

def get_client(service, region="us-west-2", role_arn=None, external_id=None):
    session = get_session(region, role_arn, external_id)
    return session.client(service)

def get_resource(service, region="us-west-2", role_arn=None, external_id=None):
    session = get_session(region, role_arn, external_id)
    return session.resource(service)