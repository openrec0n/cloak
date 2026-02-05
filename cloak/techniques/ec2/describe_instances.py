"""EC2 describe_instances technique - enumerate all EC2 instances."""

from cloak.core.models import Asset, Finding
from cloak.techniques.base import (
    BaseTechnique,
    DryRunResult,
    TechniqueMetadata,
    ValidationResult,
)


class DescribeInstancesTechnique(BaseTechnique):
    """Enumerate all EC2 instances across configured regions."""

    @property
    def metadata(self) -> TechniqueMetadata:
        """Return technique metadata."""
        return TechniqueMetadata(
            name="describe_instances",
            service="ec2",
            description="Enumerate all EC2 instances with their configuration and state",
            required_permissions=[
                "ec2:DescribeInstances",
            ],
            optional_parameters=[],
            required_parameters=[],
        )

    def validate(self) -> ValidationResult:
        """Validate configuration.

        No parameters required for this technique.
        """
        return ValidationResult(valid=True)

    def dry_run(self) -> DryRunResult:
        """Show planned actions without execution."""
        regions = self.get_regions()
        return DryRunResult(
            actions=[
                f"Call ec2:DescribeInstances in {len(regions)} region(s) (paginated API calls)",
            ],
            estimated_api_calls="1-N per region (paginated based on instance count)",
            regions=regions,
            required_permissions=self.metadata.required_permissions,
        )

    def _execute_impl(self) -> tuple[list[Asset], list[Finding]]:
        """Execute the instance enumeration."""
        assets: list[Asset] = []
        findings: list[Finding] = []

        connection_info = self.validate_connection()
        regions = self.get_regions()

        for region in regions:
            self.logger.info(f"Enumerating EC2 instances in {region}")
            ec2_client = self.get_client("ec2", region_name=region)

            try:
                paginator = ec2_client.get_paginator("describe_instances")

                for page in paginator.paginate():
                    self.logger.api_call("ec2:DescribeInstances", region=region)
                    reservations = page.get("Reservations", [])

                    for reservation in reservations:
                        instances = reservation.get("Instances", [])

                        for instance in instances:
                            instance_id = instance["InstanceId"]
                            instance_type = instance.get("InstanceType", "unknown")
                            state = instance.get("State", {}).get("Name", "unknown")
                            vpc_id = instance.get("VpcId")
                            subnet_id = instance.get("SubnetId")
                            private_ip = instance.get("PrivateIpAddress")
                            public_ip = instance.get("PublicIpAddress")
                            launch_time = instance.get("LaunchTime")
                            tags = instance.get("Tags", [])

                            # Extract name from tags if available
                            name = instance_id
                            for tag in tags:
                                if tag.get("Key") == "Name":
                                    name = tag.get("Value", instance_id)
                                    break

                            # Build ARN
                            instance_arn = (
                                f"arn:aws:ec2:{region}:{connection_info.account_id}"
                                f":instance/{instance_id}"
                            )

                            # Create asset
                            asset = Asset(
                                service="ec2",
                                resource_type="ec2_instance",
                                resource_id=instance_id,
                                resource_arn=instance_arn,
                                region=region,
                                account_id=connection_info.account_id,
                                name=name,
                            )

                            # Store full instance data
                            asset.data = {
                                "InstanceId": instance_id,
                                "InstanceType": instance_type,
                                "State": state,
                                "VpcId": vpc_id,
                                "SubnetId": subnet_id,
                                "PrivateIpAddress": private_ip,
                                "PublicIpAddress": public_ip,
                                "LaunchTime": (launch_time.isoformat() if launch_time else None),
                                "Tags": tags,
                                "ImageId": instance.get("ImageId"),
                                "KeyName": instance.get("KeyName"),
                                "SecurityGroups": instance.get("SecurityGroups", []),
                                "Architecture": instance.get("Architecture"),
                                "Platform": instance.get("Platform"),
                                "IamInstanceProfile": instance.get("IamInstanceProfile"),
                            }

                            assets.append(asset)

            except Exception as e:
                self.logger.warning(f"Failed to enumerate instances in {region}: {e}")
                # Continue with other regions
                continue

        self.logger.info(f"Successfully enumerated {len(assets)} instance(s)")
        return assets, findings

    def summarize(self, assets: list[Asset], findings: list[Finding]) -> str:
        """Generate safe summary - NO instance IDs or names.

        CRITICAL: This summary goes to Claude's context. It must NOT contain
        any instance IDs, names, IP addresses, or other sensitive identifiers.
        """
        if not assets:
            return "No EC2 instances found in the configured regions."

        # Count instances by region (safe to include)
        region_counts: dict[str, int] = {}
        for asset in assets:
            region = asset.region or "unknown"
            region_counts[region] = region_counts.get(region, 0) + 1

        # Count instances by state (safe to include)
        state_counts: dict[str, int] = {}
        for asset in assets:
            state = asset.data.get("State", "unknown") if asset.data else "unknown"
            state_counts[state] = state_counts.get(state, 0) + 1

        # Count instances by type (safe to include)
        type_counts: dict[str, int] = {}
        for asset in assets:
            instance_type = asset.data.get("InstanceType", "unknown") if asset.data else "unknown"
            type_counts[instance_type] = type_counts.get(instance_type, 0) + 1

        lines = [
            "EC2 Instance Enumeration Complete",
            "",
            f"Discovered {len(assets)} instance(s) across {len(region_counts)} region(s).",
            "",
            "Region distribution:",
        ]

        # Sort by count (descending) for better readability
        for region, count in sorted(region_counts.items(), key=lambda x: -x[1]):
            lines.append(f"  - {region}: {count} instance(s)")

        lines.append("")
        lines.append("State distribution:")
        for state, count in sorted(state_counts.items(), key=lambda x: -x[1]):
            lines.append(f"  - {state}: {count} instance(s)")

        # Show top 5 instance types
        lines.append("")
        lines.append("Instance types (top 5):")
        sorted_types = sorted(type_counts.items(), key=lambda x: -x[1])[:5]
        for instance_type, count in sorted_types:
            lines.append(f"  - {instance_type}: {count} instance(s)")

        if findings:
            lines.extend(
                [
                    "",
                    f"Findings: {len(findings)} issue(s) detected",
                ]
            )

        lines.extend(
            [
                "",
                f"Full details stored in database (execution_id: {self.execution_id})",
            ]
        )

        return "\n".join(lines)
