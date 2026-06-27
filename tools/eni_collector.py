# collectors/eni_collector.py
from .utils.aws_session import get_client
from .utils.cloudwatch import get_metric

def collect_eni_health(eni_id):
    cw = get_client("cloudwatch")
    return {
        "dropped_rx": get_metric(
            cw, "AWS/EC2", "NetworkPacketsInDropCount",
            [{"Name": "NetworkInterfaceId", "Value": eni_id}]
        ),
        "dropped_tx": get_metric(
            cw, "AWS/EC2", "NetworkPacketsOutDropCount",
            [{"Name": "NetworkInterfaceId", "Value": eni_id}]
        )
    }
