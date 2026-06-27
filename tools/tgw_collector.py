# collectors/tgw_collector.py
from .utils.aws_session import get_client
from .utils.cloudwatch import get_metric
def collect_tgw_routes(tgw_id):
    ec2 = get_client("ec2")
    return ec2.search_transit_gateway_routes(
        TransitGatewayRouteTableId=tgw_id,
        Filters=[{"Name": "type", "Values": ["static", "propagated"]}]
    )