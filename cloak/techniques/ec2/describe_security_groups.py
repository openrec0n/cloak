"""EC2 describe_security_groups technique - enumerate all security groups."""

from cloak.core.models import Asset, Finding
from cloak.techniques.base import (
    BaseTechnique,
    DryRunResult,
    TechniqueMetadata,
    ValidationResult,
)


class DescribeSecurityGroupsTechnique(BaseTechnique):
    """Enumerate all EC2 security groups across configured regions."""

    @property
    def metadata(self) -> TechniqueMetadata:
        """Return technique metadata."""
        return TechniqueMetadata(
            name="describe_security_groups",
            service="ec2",
            description="Enumerate all security groups with their ingress and egress rules",
            required_permissions=[
                "ec2:DescribeSecurityGroups",
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
                f"Call ec2:DescribeSecurityGroups in {len(regions)} region(s) (paginated API calls)",
            ],
            estimated_api_calls="1-N per region (paginated based on security group count)",
            regions=regions,
            required_permissions=self.metadata.required_permissions,
        )

    def _execute_impl(self) -> tuple[list[Asset], list[Finding]]:
        """Execute the security group enumeration."""
        assets: list[Asset] = []
        findings: list[Finding] = []

        connection_info = self.validate_connection()
        regions = self.get_regions()

        for region in regions:
            self.logger.info(f"Enumerating security groups in {region}")
            ec2_client = self.get_client("ec2", region_name=region)

            try:
                paginator = ec2_client.get_paginator("describe_security_groups")

                for page in paginator.paginate():
                    self.logger.api_call("ec2:DescribeSecurityGroups", region=region)
                    security_groups = page.get("SecurityGroups", [])

                    for sg in security_groups:
                        group_id = sg["GroupId"]
                        group_name = sg.get("GroupName", "")
                        vpc_id = sg.get("VpcId")
                        description = sg.get("Description", "")
                        owner_id = sg.get("OwnerId", connection_info.account_id)
                        ip_permissions = sg.get("IpPermissions", [])
                        ip_permissions_egress = sg.get("IpPermissionsEgress", [])
                        tags = sg.get("Tags", [])

                        # Build ARN
                        sg_arn = (
                            f"arn:aws:ec2:{region}:{connection_info.account_id}"
                            f":security-group/{group_id}"
                        )

                        # Create asset
                        asset = Asset(
                            service="ec2",
                            resource_type="ec2_security_group",
                            resource_id=group_id,
                            resource_arn=sg_arn,
                            region=region,
                            account_id=connection_info.account_id,
                            name=group_name,
                        )

                        # Store full security group data
                        asset.data = {
                            "GroupId": group_id,
                            "GroupName": group_name,
                            "VpcId": vpc_id,
                            "Description": description,
                            "OwnerId": owner_id,
                            "IpPermissions": ip_permissions,
                            "IpPermissionsEgress": ip_permissions_egress,
                            "Tags": tags,
                        }

                        assets.append(asset)

            except Exception as e:
                self.logger.warning(f"Failed to enumerate security groups in {region}: {e}")
                # Continue with other regions
                continue

        self.logger.info(f"Successfully enumerated {len(assets)} security group(s)")
        return assets, findings

    def summarize(self, assets: list[Asset], findings: list[Finding]) -> str:
        """Generate safe summary - NO security group IDs or names.

        CRITICAL: This summary goes to Claude's context. It must NOT contain
        any security group IDs, names, VPC IDs, or other sensitive identifiers.
        """
        if not assets:
            return "No security groups found in the configured regions."

        # Count security groups by region (safe to include)
        region_counts: dict[str, int] = {}
        for asset in assets:
            region = asset.region or "unknown"
            region_counts[region] = region_counts.get(region, 0) + 1

        # Count security groups with inbound rules vs no inbound rules
        has_inbound_count = 0
        has_outbound_count = 0
        for asset in assets:
            if asset.data:
                if asset.data.get("IpPermissions"):
                    has_inbound_count += 1
                if asset.data.get("IpPermissionsEgress"):
                    has_outbound_count += 1

        # Count by VPC (just count unique VPCs, not VPC IDs)
        vpc_count = len({asset.data.get("VpcId", "no-vpc") for asset in assets if asset.data})

        lines = [
            "EC2 Security Group Enumeration Complete",
            "",
            f"Discovered {len(assets)} security group(s) across {len(region_counts)} region(s).",
            "",
            "Region distribution:",
        ]

        # Sort by count (descending) for better readability
        for region, count in sorted(region_counts.items(), key=lambda x: -x[1]):
            lines.append(f"  - {region}: {count} security group(s)")

        lines.append("")
        lines.append("Rule statistics:")
        lines.append(f"  - Security groups with inbound rules: {has_inbound_count}")
        lines.append(f"  - Security groups with outbound rules: {has_outbound_count}")
        lines.append(f"  - Unique VPCs: {vpc_count}")

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
