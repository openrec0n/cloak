"""IAM list_policies technique - enumerate IAM policies."""

from cloak.core.config import ParameterSpec
from cloak.core.models import Asset, Finding
from cloak.techniques.base import (
    BaseTechnique,
    DryRunResult,
    TechniqueMetadata,
    ValidationResult,
)


class ListPoliciesTechnique(BaseTechnique):
    """List IAM policies in the AWS account."""

    # Valid scope values
    VALID_SCOPES = ["Local", "AWS", "All"]

    @property
    def metadata(self) -> TechniqueMetadata:
        """Return technique metadata."""
        return TechniqueMetadata(
            name="list_policies",
            service="iam",
            description="List IAM policies with configurable scope (Local, AWS, or All)",
            required_permissions=[
                "iam:ListPolicies",
            ],
            required_parameters=[
                ParameterSpec(
                    name="scope",
                    param_type="str",
                    required=True,
                    description="Policy scope: 'Local' (customer-managed), 'AWS' (AWS-managed), or 'All'",
                    choices=["Local", "AWS", "All"],
                ),
            ],
            optional_parameters=[],
        )

    def validate(self) -> ValidationResult:
        """Validate configuration."""
        result = ValidationResult(valid=True)

        scope = self.config.parameters.get("scope")
        if not scope:
            result.add_error("scope parameter is required")
            return result

        if not isinstance(scope, str):
            result.add_error("scope must be a string")
            return result

        if scope not in self.VALID_SCOPES:
            result.add_error(f"scope must be one of: {', '.join(self.VALID_SCOPES)}")
            return result

        return result

    def dry_run(self) -> DryRunResult:
        """Show planned actions without execution."""
        scope = self.config.parameters.get("scope", "Local")

        return DryRunResult(
            actions=[
                f"Call iam:ListPolicies with Scope='{scope}' (paginated API calls)",
            ],
            estimated_api_calls="1-N (paginated based on policy count)",
            regions=["global"],
            required_permissions=self.metadata.required_permissions,
        )

    def _execute_impl(self) -> tuple[list[Asset], list[Finding]]:
        """Execute the policy enumeration."""
        assets: list[Asset] = []
        findings: list[Finding] = []

        # Get IAM client (IAM is a global service)
        iam_client = self.get_client("iam")
        connection_info = self.validate_connection()

        # Get scope parameter
        scope = self.config.parameters.get("scope", "Local")

        # List policies using paginator
        self.logger.info(f"Listing IAM policies with scope: {scope}")
        try:
            paginator = iam_client.get_paginator("list_policies")
            policy_count = 0

            # Build pagination config based on scope
            paginate_kwargs = {}
            if scope != "All":
                paginate_kwargs["Scope"] = scope

            for page in paginator.paginate(**paginate_kwargs):
                self.logger.api_call("iam:ListPolicies", scope=scope)
                policies = page.get("Policies", [])

                for policy in policies:
                    policy_count += 1
                    policy_name = policy["PolicyName"]
                    policy_id = policy["PolicyId"]
                    policy_arn = policy["Arn"]
                    path = policy.get("Path", "/")
                    default_version_id = policy.get("DefaultVersionId", "v1")
                    attachment_count = policy.get("AttachmentCount", 0)
                    is_attachable = policy.get("IsAttachable", True)
                    create_date = policy["CreateDate"]
                    update_date = policy.get("UpdateDate")

                    # Create asset
                    asset = Asset(
                        service="iam",
                        resource_type="iam_policy",
                        resource_id=policy_id,
                        resource_arn=policy_arn,
                        region="global",
                        account_id=connection_info.account_id,
                        name=policy_name,
                    )

                    # Store full policy data
                    asset.data = {
                        "PolicyName": policy_name,
                        "PolicyId": policy_id,
                        "Arn": policy_arn,
                        "Path": path,
                        "DefaultVersionId": default_version_id,
                        "AttachmentCount": attachment_count,
                        "IsAttachable": is_attachable,
                        "CreateDate": create_date.isoformat(),
                        "UpdateDate": update_date.isoformat() if update_date else None,
                        "Scope": scope,
                    }

                    assets.append(asset)

            self.logger.info(f"Found {policy_count} policy(ies)")

        except Exception as e:
            self.logger.error(f"Failed to list policies: {e}")
            raise

        self.logger.info(f"Successfully enumerated {len(assets)} policy(ies)")
        return assets, findings

    def summarize(self, assets: list[Asset], findings: list[Finding]) -> str:
        """Generate safe summary - NO policy names.

        CRITICAL: This summary goes to Claude's context. It must NOT contain
        any policy names, ARNs, or other sensitive identifiers.
        """
        scope = self.config.parameters.get("scope", "Local")

        if not assets:
            return f"No IAM policies found with scope '{scope}' in this AWS account."

        # Count attached vs unattached policies (safe to include)
        attached_count = 0
        unattached_count = 0
        for asset in assets:
            attachment_count = asset.data.get("AttachmentCount", 0) if asset.data else 0
            if attachment_count > 0:
                attached_count += 1
            else:
                unattached_count += 1

        lines = [
            f"IAM Policy Enumeration Complete (Scope: {scope})",
            "",
            f"Discovered {len(assets)} policy(ies).",
            "",
            "Attachment status:",
            f"  - Attached: {attached_count}",
            f"  - Unattached: {unattached_count}",
        ]

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
