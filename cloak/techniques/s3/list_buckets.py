"""S3 list_buckets technique - enumerate all S3 buckets."""

from cloak.core.models import Asset, Finding
from cloak.techniques.base import (
    BaseTechnique,
    DryRunResult,
    TechniqueMetadata,
    ValidationResult,
)


class ListBucketsTechnique(BaseTechnique):
    """List all S3 buckets in the AWS account."""

    @property
    def metadata(self) -> TechniqueMetadata:
        """Return technique metadata."""
        return TechniqueMetadata(
            name="list_buckets",
            service="s3",
            description="List all S3 buckets with their regions",
            required_permissions=[
                "s3:ListAllMyBuckets",
                "s3:GetBucketLocation",
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
        return DryRunResult(
            actions=[
                "Call s3:ListAllMyBuckets (1 API call)",
                "Call s3:GetBucketLocation for each bucket (N API calls)",
            ],
            estimated_api_calls="1 + N (where N = number of buckets)",
            regions=["global"],
            required_permissions=self.metadata.required_permissions,
        )

    def _execute_impl(self) -> tuple[list[Asset], list[Finding]]:
        """Execute the bucket enumeration."""
        assets: list[Asset] = []
        findings: list[Finding] = []

        # Get S3 client (S3 is a global service)
        s3_client = self.get_client("s3")
        connection_info = self.validate_connection()

        # List all buckets
        self.logger.info("Listing all S3 buckets")
        try:
            response = s3_client.list_buckets()
            self.logger.api_call("s3:ListBuckets")
        except Exception as e:
            self.logger.error(f"Failed to list buckets: {e}")
            raise

        buckets = response.get("Buckets", [])
        self.logger.info(f"Found {len(buckets)} bucket(s)")

        # Process each bucket
        for bucket in buckets:
            bucket_name = bucket["Name"]
            creation_date = bucket["CreationDate"]

            # Get bucket location
            try:
                location_response = s3_client.get_bucket_location(Bucket=bucket_name)
                # LocationConstraint is None for us-east-1
                region = location_response.get("LocationConstraint") or "us-east-1"
                self.logger.api_call("s3:GetBucketLocation")
            except Exception as e:
                self.logger.warning(f"Could not get location for bucket: {e}")
                region = "unknown"

            # Create asset
            asset = Asset(
                service="s3",
                resource_type="s3_bucket",
                resource_id=bucket_name,
                resource_arn=f"arn:aws:s3:::{bucket_name}",
                region=region,
                account_id=connection_info.account_id,
                name=bucket_name,
            )

            # Store full bucket data
            asset.data = {
                "Name": bucket_name,
                "CreationDate": creation_date.isoformat(),
                "Region": region,
            }

            assets.append(asset)

        self.logger.info(f"Successfully enumerated {len(assets)} bucket(s)")
        return assets, findings

    def summarize(self, assets: list[Asset], findings: list[Finding]) -> str:
        """Generate safe summary - NO bucket names.

        CRITICAL: This summary goes to Claude's context. It must NOT contain
        any bucket names, ARNs, or other sensitive identifiers.
        """
        if not assets:
            return "No S3 buckets found in this AWS account."

        # Count buckets by region (safe to include)
        region_counts: dict[str, int] = {}
        for asset in assets:
            region = asset.region or "unknown"
            region_counts[region] = region_counts.get(region, 0) + 1

        lines = [
            "S3 Bucket Enumeration Complete",
            "",
            f"Discovered {len(assets)} bucket(s) across {len(region_counts)} region(s).",
            "",
            "Region distribution:",
        ]

        # Sort by count (descending) for better readability
        for region, count in sorted(region_counts.items(), key=lambda x: -x[1]):
            lines.append(f"  - {region}: {count} bucket(s)")

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
