"""EC2 describe_vpcs technique - enumerate all VPCs."""

from cloak.core.models import Asset, Finding
from cloak.techniques.base import (
    BaseTechnique,
    DryRunResult,
    TechniqueMetadata,
    ValidationResult,
)


class DescribeVpcsTechnique(BaseTechnique):
    """Enumerate all VPCs across configured regions."""

    @property
    def metadata(self) -> TechniqueMetadata:
        """Return technique metadata."""
        return TechniqueMetadata(
            name="describe_vpcs",
            service="ec2",
            description="Enumerate all VPCs with their CIDR blocks and configuration",
            required_permissions=[
                "ec2:DescribeVpcs",
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
                f"Call ec2:DescribeVpcs in {len(regions)} region(s)",
            ],
            estimated_api_calls=f"{len(regions)} (1 per region)",
            regions=regions,
            required_permissions=self.metadata.required_permissions,
        )

    def _execute_impl(self) -> tuple[list[Asset], list[Finding]]:
        """Execute the VPC enumeration."""
        assets: list[Asset] = []
        findings: list[Finding] = []

        connection_info = self.validate_connection()
        regions = self.get_regions()

        for region in regions:
            self.logger.info(f"Enumerating VPCs in {region}")
            ec2_client = self.get_client("ec2", region_name=region)

            try:
                # describe_vpcs doesn't have a paginator, use direct call
                response = ec2_client.describe_vpcs()
                self.logger.api_call("ec2:DescribeVpcs", region=region)
                vpcs = response.get("Vpcs", [])

                for vpc in vpcs:
                    vpc_id = vpc["VpcId"]
                    cidr_block = vpc.get("CidrBlock", "")
                    state = vpc.get("State", "unknown")
                    is_default = vpc.get("IsDefault", False)
                    owner_id = vpc.get("OwnerId", connection_info.account_id)
                    tags = vpc.get("Tags", [])
                    cidr_block_associations = vpc.get("CidrBlockAssociationSet", [])
                    ipv6_cidr_block_associations = vpc.get("Ipv6CidrBlockAssociationSet", [])

                    # Extract name from tags if available
                    name = vpc_id
                    for tag in tags:
                        if tag.get("Key") == "Name":
                            name = tag.get("Value", vpc_id)
                            break

                    # Build ARN
                    vpc_arn = f"arn:aws:ec2:{region}:{connection_info.account_id}" f":vpc/{vpc_id}"

                    # Create asset
                    asset = Asset(
                        service="ec2",
                        resource_type="ec2_vpc",
                        resource_id=vpc_id,
                        resource_arn=vpc_arn,
                        region=region,
                        account_id=connection_info.account_id,
                        name=name,
                    )

                    # Store full VPC data
                    asset.data = {
                        "VpcId": vpc_id,
                        "CidrBlock": cidr_block,
                        "State": state,
                        "IsDefault": is_default,
                        "OwnerId": owner_id,
                        "Tags": tags,
                        "CidrBlockAssociationSet": cidr_block_associations,
                        "Ipv6CidrBlockAssociationSet": ipv6_cidr_block_associations,
                        "DhcpOptionsId": vpc.get("DhcpOptionsId"),
                        "InstanceTenancy": vpc.get("InstanceTenancy"),
                    }

                    assets.append(asset)

            except Exception as e:
                self.logger.warning(f"Failed to enumerate VPCs in {region}: {e}")
                # Continue with other regions
                continue

        self.logger.info(f"Successfully enumerated {len(assets)} VPC(s)")
        return assets, findings

    def summarize(self, assets: list[Asset], findings: list[Finding]) -> str:
        """Generate safe summary - NO VPC IDs or CIDR blocks.

        CRITICAL: This summary goes to Claude's context. It must NOT contain
        any VPC IDs, CIDR blocks, or other sensitive identifiers.
        """
        if not assets:
            return "No VPCs found in the configured regions."

        # Count VPCs by region (safe to include)
        region_counts: dict[str, int] = {}
        for asset in assets:
            region = asset.region or "unknown"
            region_counts[region] = region_counts.get(region, 0) + 1

        # Count default vs custom VPCs
        default_count = 0
        custom_count = 0
        for asset in assets:
            if asset.data:
                if asset.data.get("IsDefault"):
                    default_count += 1
                else:
                    custom_count += 1

        # Count by state
        state_counts: dict[str, int] = {}
        for asset in assets:
            state = asset.data.get("State", "unknown") if asset.data else "unknown"
            state_counts[state] = state_counts.get(state, 0) + 1

        lines = [
            "EC2 VPC Enumeration Complete",
            "",
            f"Discovered {len(assets)} VPC(s) across {len(region_counts)} region(s).",
            "",
            "Region distribution:",
        ]

        # Sort by count (descending) for better readability
        for region, count in sorted(region_counts.items(), key=lambda x: -x[1]):
            lines.append(f"  - {region}: {count} VPC(s)")

        lines.append("")
        lines.append("VPC types:")
        lines.append(f"  - Default VPCs: {default_count}")
        lines.append(f"  - Custom VPCs: {custom_count}")

        if len(state_counts) > 1 or "available" not in state_counts:
            lines.append("")
            lines.append("State distribution:")
            for state, count in sorted(state_counts.items(), key=lambda x: -x[1]):
                lines.append(f"  - {state}: {count} VPC(s)")

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
