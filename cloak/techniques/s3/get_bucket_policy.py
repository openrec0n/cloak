"""S3 get_bucket_policy technique - retrieve bucket policies for S3 buckets."""

import json

from cloak.core.config import ParameterSpec
from cloak.core.models import Asset, Finding
from cloak.techniques.base import (
    BaseTechnique,
    DryRunResult,
    TechniqueMetadata,
    ValidationResult,
)


class GetBucketPolicyTechnique(BaseTechnique):
    """Get bucket policy for S3 buckets."""

    @property
    def metadata(self) -> TechniqueMetadata:
        """Return technique metadata."""
        return TechniqueMetadata(
            name="get_bucket_policy",
            service="s3",
            description="Retrieve bucket policy configuration for S3 buckets",
            required_permissions=[
                "s3:GetBucketPolicy",
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
                "Call s3:GetBucketPolicy for each bucket (N API calls)",
            ]
            estimated_api_calls = "1 + N (where N = number of buckets)"
        else:
            actions = [
                f"Call s3:GetBucketPolicy for bucket '{bucket_name}' (1 API call)",
            ]
            estimated_api_calls = "1"

        return DryRunResult(
            actions=actions,
            estimated_api_calls=estimated_api_calls,
            regions=["global"],  # S3 is global, but buckets have regions
            required_permissions=self.metadata.required_permissions,
        )

    def _execute_impl(self) -> tuple[list[Asset], list[Finding]]:
        """Execute the policy enumeration."""
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
            self.logger.info("Listing all S3 buckets for policy enumeration")
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
            self.logger.info(f"Getting policy for bucket: {bucket}")
            try:
                # Get bucket policy
                policy_response = s3_client.get_bucket_policy(Bucket=bucket)
                self.logger.api_call("s3:GetBucketPolicy", bucket=bucket)

                # Get bucket location for region
                try:
                    location_response = s3_client.get_bucket_location(Bucket=bucket)
                    region = location_response.get("LocationConstraint") or "us-east-1"
                except Exception as e:
                    self.logger.warning(f"Could not get location for bucket {bucket}: {e}")
                    region = "unknown"

                # Parse policy JSON
                policy_text = policy_response.get("Policy", "{}")
                try:
                    policy_json = json.loads(policy_text)
                except json.JSONDecodeError as e:
                    self.logger.warning(f"Failed to parse policy JSON for bucket {bucket}: {e}")
                    policy_json = {
                        "error": "Failed to parse policy JSON",
                        "raw_policy": policy_text,
                    }

                # Create asset with full policy data
                asset = Asset(
                    service="s3",
                    resource_type="s3_bucket_policy",
                    resource_id=bucket,
                    resource_arn=f"arn:aws:s3:::{bucket}",
                    region=region,
                    account_id=connection_info.account_id,
                    name=bucket,
                )

                # Store full policy data
                asset.data = {
                    "Policy": policy_json,
                    "PolicyText": policy_text,  # Keep raw text as well
                }

                assets.append(asset)

            except Exception as e:
                error_msg = str(e)
                # Handle common errors gracefully
                if "NoSuchBucketPolicy" in error_msg:
                    # Bucket has no policy - this is normal, not an error
                    self.logger.info(f"Bucket {bucket} has no policy attached")
                    # Don't create an asset for buckets without policies
                    continue
                elif "AccessDenied" in error_msg or "403" in error_msg:
                    self.logger.warning(f"Access denied for bucket {bucket} policy: {e}")
                    # Continue with other buckets
                    continue
                elif "NoSuchBucket" in error_msg or "404" in error_msg:
                    self.logger.warning(f"Bucket {bucket} not found: {e}")
                    # Continue with other buckets
                    continue
                else:
                    self.logger.error(f"Failed to get policy for bucket {bucket}: {e}")
                    # Re-raise unexpected errors
                    raise

        self.logger.info(f"Successfully retrieved policies for {len(assets)} bucket(s)")
        return assets, findings

    def summarize(self, assets: list[Asset], findings: list[Finding]) -> str:
        """Generate safe summary - NO bucket names or policy content.

        CRITICAL: This summary goes to Claude's context. It must NOT contain
        any bucket names, ARNs, account IDs, or policy content.
        """
        if not assets:
            return "No S3 bucket policies retrieved. This may indicate no buckets exist, no buckets have policies attached, access was denied, or buckets were not found."

        # Count buckets by region (safe to include)
        region_counts: dict[str, int] = {}
        statement_counts: dict[str, int] = {}  # Count statements by effect

        for asset in assets:
            region = asset.region or "unknown"
            region_counts[region] = region_counts.get(region, 0) + 1

            # Count policy statements (safe - just effect types, no identifiers)
            policy_data = asset.data or {}
            policy = policy_data.get("Policy", {})
            statements = policy.get("Statement", [])
            for statement in statements:
                effect = statement.get("Effect", "UNKNOWN")
                statement_counts[effect] = statement_counts.get(effect, 0) + 1

        lines = [
            "S3 Bucket Policy Enumeration Complete",
            "",
            f"Retrieved policies for {len(assets)} bucket(s) across {len(region_counts)} region(s).",
            "",
        ]

        if region_counts:
            lines.append("Region distribution:")
            for region, count in sorted(region_counts.items(), key=lambda x: -x[1]):
                lines.append(f"  - {region}: {count} bucket(s)")

        if statement_counts:
            lines.extend(
                [
                    "",
                    "Policy statement effects found:",
                ]
            )
            for effect, count in sorted(statement_counts.items()):
                lines.append(f"  - {effect}: {count} statement(s)")

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
                f"Full policy details stored in database (execution_id: {self.execution_id})",
            ]
        )

        return "\n".join(lines)
