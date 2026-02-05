"""EC2 enumeration techniques."""

from cloak.techniques.ec2.describe_instances import DescribeInstancesTechnique
from cloak.techniques.ec2.describe_security_groups import DescribeSecurityGroupsTechnique
from cloak.techniques.ec2.describe_vpcs import DescribeVpcsTechnique

__all__ = [
    "DescribeInstancesTechnique",
    "DescribeSecurityGroupsTechnique",
    "DescribeVpcsTechnique",
]

# Technique registry for dynamic loading
TECHNIQUES = {
    "describe_instances": DescribeInstancesTechnique,
    "describe_security_groups": DescribeSecurityGroupsTechnique,
    "describe_vpcs": DescribeVpcsTechnique,
}
