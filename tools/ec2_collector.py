# collectors/ec2_collector.py
from .utils.aws_session import get_client
from .utils.cloudwatch import get_metric

def collect_ec2_network_health(instance_id):
    cw = get_client("cloudwatch")
    metrics = {}

    metrics["network_in"] = get_metric(
        cw, "AWS/EC2", "NetworkIn",
        [{"Name": "InstanceId", "Value": instance_id}]
    )

    metrics["network_out"] = get_metric(
        cw, "AWS/EC2", "NetworkOut",
        [{"Name": "InstanceId", "Value": instance_id}]
    )

    metrics["packet_loss"] = get_metric(
        cw, "AWS/EC2", "CPUPacketDropCount",
        [{"Name": "InstanceId", "Value": instance_id}]
    )

    return metrics
