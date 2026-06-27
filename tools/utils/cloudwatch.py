# utils/cloudwatch.py
from datetime import datetime, timedelta

def get_metric(client, namespace, metric, dimensions):
    end = datetime.utcnow()
    start = end - timedelta(minutes=5)

    return client.get_metric_statistics(
        Namespace=namespace,
        MetricName=metric,
        Dimensions=dimensions,
        StartTime=start,
        EndTime=end,
        Period=60,
        Statistics=["Average", "Sum", "Maximum"]
    )
