"""IAM list_roles technique - enumerate all IAM roles."""

from cloak.core.models import Asset, Finding
from cloak.techniques.base import (
    BaseTechnique,
    DryRunResult,
    TechniqueMetadata,
    ValidationResult,
)


class ListRolesTechnique(BaseTechnique):
    """List all IAM roles in the AWS account."""

    @property
    def metadata(self) -> TechniqueMetadata:
        """Return technique metadata."""
        return TechniqueMetadata(
            name="list_roles",
            service="iam",
            description="List all IAM roles with their trust policies and paths",
            required_permissions=[
                "iam:ListRoles",
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
                "Call iam:ListRoles (paginated API calls)",
            ],
            estimated_api_calls="1-N (paginated based on role count)",
            regions=["global"],
            required_permissions=self.metadata.required_permissions,
        )

    def _execute_impl(self) -> tuple[list[Asset], list[Finding]]:
        """Execute the role enumeration."""
        assets: list[Asset] = []
        findings: list[Finding] = []

        # Get IAM client (IAM is a global service)
        iam_client = self.get_client("iam")
        connection_info = self.validate_connection()

        # List all roles using paginator
        self.logger.info("Listing all IAM roles")
        try:
            paginator = iam_client.get_paginator("list_roles")
            role_count = 0

            for page in paginator.paginate():
                self.logger.api_call("iam:ListRoles")
                roles = page.get("Roles", [])

                for role in roles:
                    role_count += 1
                    role_name = role["RoleName"]
                    role_id = role["RoleId"]
                    role_arn = role["Arn"]
                    path = role.get("Path", "/")
                    create_date = role["CreateDate"]
                    description = role.get("Description")
                    max_session_duration = role.get("MaxSessionDuration", 3600)
                    assume_role_policy = role.get("AssumeRolePolicyDocument", {})

                    # Create asset
                    asset = Asset(
                        service="iam",
                        resource_type="iam_role",
                        resource_id=role_id,
                        resource_arn=role_arn,
                        region="global",
                        account_id=connection_info.account_id,
                        name=role_name,
                    )

                    # Store full role data
                    asset.data = {
                        "RoleName": role_name,
                        "RoleId": role_id,
                        "Arn": role_arn,
                        "Path": path,
                        "CreateDate": create_date.isoformat(),
                        "Description": description,
                        "MaxSessionDuration": max_session_duration,
                        "AssumeRolePolicyDocument": assume_role_policy,
                    }

                    assets.append(asset)

            self.logger.info(f"Found {role_count} role(s)")

        except Exception as e:
            self.logger.error(f"Failed to list roles: {e}")
            raise

        self.logger.info(f"Successfully enumerated {len(assets)} role(s)")
        return assets, findings

    def summarize(self, assets: list[Asset], findings: list[Finding]) -> str:
        """Generate safe summary - NO role names.

        CRITICAL: This summary goes to Claude's context. It must NOT contain
        any role names, ARNs, or other sensitive identifiers.
        """
        if not assets:
            return "No IAM roles found in this AWS account."

        # Count roles by path (safe to include)
        path_counts: dict[str, int] = {}
        for asset in assets:
            path = asset.data.get("Path", "/") if asset.data else "/"
            path_counts[path] = path_counts.get(path, 0) + 1

        lines = [
            "IAM Role Enumeration Complete",
            "",
            f"Discovered {len(assets)} role(s).",
            "",
            "Path distribution:",
        ]

        # Sort by count (descending) for better readability
        for path, count in sorted(path_counts.items(), key=lambda x: -x[1]):
            lines.append(f"  - {path}: {count} role(s)")

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
