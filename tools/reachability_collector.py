# collectors/reachability_collector.py
from .utils.aws_session import get_client
from .utils.cloudwatch import get_metric
def run_reachability_analysis(source_eni, dest_eni):
    client = get_client("ec2")
    response = client.start_network_insights_analysis(
        NetworkInsightsPathId=client.create_network_insights_path(
            Source=source_eni,
            Destination=dest_eni,
            Protocol="TCP"
        )["NetworkInsightsPath"]["NetworkInsightsPathId"]
    )
    return response
