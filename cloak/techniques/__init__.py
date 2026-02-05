"""Technique implementations for CLOAK.

Techniques are organized by AWS service:
- s3: S3 bucket enumeration techniques
- iam: IAM user, role, policy enumeration
- ec2: EC2 instance, security group, VPC enumeration
- lambda_: Lambda function enumeration
- sts: STS role assumption techniques
"""

from cloak.techniques.base import (
    BaseTechnique,
    DryRunResult,
    ExecutionResult,
    TechniqueMetadata,
    ValidationResult,
)

__all__ = [
    "BaseTechnique",
    "DryRunResult",
    "ExecutionResult",
    "TechniqueMetadata",
    "ValidationResult",
]
