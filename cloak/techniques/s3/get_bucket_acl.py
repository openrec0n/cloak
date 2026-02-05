"""S3 get_bucket_acl technique - retrieve ACL configuration for S3 buckets."""

from typing import Any

from cloak.core.config import ParameterSpec
from cloak.core.models import Asset, Finding
from cloak.techniques.base import (
    BaseTechnique,
    DryRunResult,
    TechniqueMetadata,
    ValidationResult,
)


class GetBucketAclTechnique(BaseTechnique):
    """Get ACL configuration for S3 buckets."""

    @property
    def metadata(self) -> TechniqueMetadata:
        """Return technique metadata."""
        return TechniqueMetadata(
            name="get_bucket_acl",
            service="s3",
            description="Retrieve Access Control List (ACL) configuration for S3 buckets",
            required_permissions=[
                "s3:GetBucketAcl",
                "s3:ListAllMyBuckets",  # Required when bucket_name is "all"
            ],
            optional_parameters=[],
            required_parameters=[
                ParameterSpec(
                    name="bucket_name",
                    param_type="str",
                    required=True,
                    description="Name of the bucket to check, or 'all' to check all buckets",
                ),
            ],
        )

    def validate(self) -> ValidationResult:
        """Validate configuration.

        Requires bucket_name parameter.
        """
        result = ValidationResult(valid=True)

        bucket_name = self.config.parameters.get("bucket_name")
        if not bucket_name:
            result.add_error("bucket_name parameter is required")
            return result

        if not isinstance(bucket_name, str):
            result.add_error("bucket_name must be a string")
            return result

        if bucket_name.strip() == "":
            result.add_error("bucket_name cannot be empty")
            return result

        return result

    def dry_run(self) -> DryRunResult:
        """Show planned actions without execution."""
        bucket_name = self.config.parameters.get("bucket_name", "unknown")

        if bucket_name == "all":
            actions = [
                "Call s3:ListAllMyBuckets (1 API call)",
                "Call s3:GetBucketAcl for each bucket (N API calls)",
            ]
            estimated_api_calls = "1 + N (where N = number of buckets)"
        else:
            actions = [
                f"Call s3:GetBucketAcl for bucket '{bucket_name}' (1 API call)",
            ]
            estimated_api_calls = "1"

        return DryRunResult(
            actions=actions,
            estimated_api_calls=estimated_api_calls,
            regions=["global"],  # S3 is global, but buckets have regions
            required_permissions=self.metadata.required_permissions,
        )

    def _execute_impl(self) -> tuple[list[Asset], list[Finding]]:
        """Execute the ACL enumeration."""
        assets: list[Asset] = []
        findings: list[Finding] = []

        bucket_name = self.config.parameters.get("bucket_name")
        if not bucket_name:
            raise ValueError("bucket_name parameter is required")

        # Get S3 client
        s3_client = self.get_client("s3")
        connection_info = self.validate_connection()

        # Determine which buckets to check
        buckets_to_check: list[str] = []
        if bucket_name == "all":
            # List all buckets first
            self.logger.info("Listing all S3 buckets for ACL enumeration")
            try:
                response = s3_client.list_buckets()
                self.logger.api_call("s3:ListBuckets")
                buckets_to_check = [bucket["Name"] for bucket in response.get("Buckets", [])]
                self.logger.info(f"Found {len(buckets_to_check)} bucket(s) to check")
            except Exception as e:
                self.logger.error(f"Failed to list buckets: {e}")
                raise
        else:
            buckets_to_check = [bucket_name]

        # Process each bucket
        for bucket in buckets_to_check:
            self.logger.info(f"Getting ACL for bucket: {bucket}")
            try:
                # Get bucket ACL
                acl_response = s3_client.get_bucket_acl(Bucket=bucket)
                self.logger.api_call("s3:GetBucketAcl", bucket=bucket)

                # Get bucket location for region
                try:
                    location_response = s3_client.get_bucket_location(Bucket=bucket)
                    region = location_response.get("LocationConstraint") or "us-east-1"
                except Exception as e:
                    self.logger.warning(f"Could not get location for bucket {bucket}: {e}")
                    region = "unknown"

                # Create asset with full ACL data
                asset = Asset(
                    service="s3",
                    resource_type="s3_bucket_acl",
                    resource_id=bucket,
                    resource_arn=f"arn:aws:s3:::{bucket}",
                    region=region,
                    account_id=connection_info.account_id,
                    name=bucket,
                )

                # Store full ACL data (convert datetime objects to strings for JSON)
                acl_data: dict[str, Any] = {
                    "Owner": {
                        "ID": acl_response.get("Owner", {}).get("ID"),
                        "DisplayName": acl_response.get("Owner", {}).get("DisplayName"),
                    },
                    "Grants": [],
                }

                # Process grants (convert any datetime objects)
                for grant in acl_response.get("Grants", []):
                    grant_data = {
                        "Grantee": {
                            "Type": grant.get("Grantee", {}).get("Type"),
                            "ID": grant.get("Grantee", {}).get("ID"),
                            "DisplayName": grant.get("Grantee", {}).get("DisplayName"),
                            "URI": grant.get("Grantee", {}).get("URI"),
                        },
                        "Permission": grant.get("Permission"),
                    }
                    # Remove None values
                    grant_data["Grantee"] = {
                        k: v for k, v in grant_data["Grantee"].items() if v is not None
                    }
                    acl_data["Grants"].append(grant_data)

                asset.data = acl_data
                assets.append(asset)

            except Exception as e:
                error_msg = str(e)
                # Handle common errors gracefully
                if "AccessDenied" in error_msg or "403" in error_msg:
                    self.logger.warning(f"Access denied for bucket {bucket} ACL: {e}")
                    # Continue with other buckets
                    continue
                elif "NoSuchBucket" in error_msg or "404" in error_msg:
                    self.logger.warning(f"Bucket {bucket} not found: {e}")
                    # Continue with other buckets
                    continue
                else:
                    self.logger.error(f"Failed to get ACL for bucket {bucket}: {e}")
                    # Re-raise unexpected errors
                    raise

        self.logger.info(f"Successfully retrieved ACLs for {len(assets)} bucket(s)")
        return assets, findings

    def summarize(self, assets: list[Asset], findings: list[Finding]) -> str:
        """Generate safe summary - NO bucket names or grantee details.

        CRITICAL: This summary goes to Claude's context. It must NOT contain
        any bucket names, ARNs, account IDs, or grantee information.
        """
        if not assets:
            return "No S3 bucket ACLs retrieved. This may indicate no buckets exist, access was denied, or buckets were not found."

        # Count buckets by region (safe to include)
        region_counts: dict[str, int] = {}
        grant_counts: dict[str, int] = {}  # Count grants by permission type

        for asset in assets:
            region = asset.region or "unknown"
            region_counts[region] = region_counts.get(region, 0) + 1

            # Count grants (safe - just permission types, no identifiers)
            acl_data = asset.data or {}
            grants = acl_data.get("Grants", [])
            for grant in grants:
                permission = grant.get("Permission", "UNKNOWN")
                grant_counts[permission] = grant_counts.get(permission, 0) + 1

        lines = [
            "S3 Bucket ACL Enumeration Complete",
            "",
            f"Retrieved ACLs for {len(assets)} bucket(s) across {len(region_counts)} region(s).",
            "",
        ]

        if region_counts:
            lines.append("Region distribution:")
            for region, count in sorted(region_counts.items(), key=lambda x: -x[1]):
                lines.append(f"  - {region}: {count} bucket(s)")

        if grant_counts:
            lines.extend(
                [
                    "",
                    "Permission grants found:",
                ]
            )
            for permission, count in sorted(grant_counts.items()):
                lines.append(f"  - {permission}: {count} grant(s)")

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
                f"Full ACL details stored in database (execution_id: {self.execution_id})",
            ]
        )

        return "\n".join(lines)
