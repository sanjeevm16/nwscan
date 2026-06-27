# collectors/elb_collector.py
from .utils.aws_session import get_client
from .utils.cloudwatch import get_metric
def collect_elb_health(lb_name):
    cw = get_client("cloudwatch")
    return {
        "healthy_hosts": get_metric(
            cw, "AWS/ApplicationELB", "HealthyHostCount",
            [{"Name": "LoadBalancer", "Value": lb_name}]
        ),
        "latency": get_metric(
            cw, "AWS/ApplicationELB", "TargetResponseTime",
            [{"Name": "LoadBalancer", "Value": lb_name}]
        )
    }