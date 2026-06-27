# main.py
from .ec2_collector import collect_ec2_network_health
from .eni_collector import collect_eni_health
from .elb_collector import collect_elb_health

def run():
    results = {
        "ec2": collect_ec2_network_health("i-1234567890"),
        "eni": collect_eni_health("eni-1234567890"),
        "elb": collect_elb_health("app/my-lb/123abc")
    }

    print(results)
nw
