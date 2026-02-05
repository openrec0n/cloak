"""IAM list_users technique - enumerate all IAM users."""

from cloak.core.models import Asset, Finding
from cloak.techniques.base import (
    BaseTechnique,
    DryRunResult,
    TechniqueMetadata,
    ValidationResult,
)


class ListUsersTechnique(BaseTechnique):
    """List all IAM users in the AWS account."""

    @property
    def metadata(self) -> TechniqueMetadata:
        """Return technique metadata."""
        return TechniqueMetadata(
            name="list_users",
            service="iam",
            description="List all IAM users with their creation dates and paths",
            required_permissions=[
                "iam:ListUsers",
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
                "Call iam:ListUsers (paginated API calls)",
            ],
            estimated_api_calls="1-N (paginated based on user count)",
            regions=["global"],
            required_permissions=self.metadata.required_permissions,
        )

    def _execute_impl(self) -> tuple[list[Asset], list[Finding]]:
        """Execute the user enumeration."""
        assets: list[Asset] = []
        findings: list[Finding] = []

        # Get IAM client (IAM is a global service)
        iam_client = self.get_client("iam")
        connection_info = self.validate_connection()

        # List all users using paginator
        self.logger.info("Listing all IAM users")
        try:
            paginator = iam_client.get_paginator("list_users")
            user_count = 0

            for page in paginator.paginate():
                self.logger.api_call("iam:ListUsers")
                users = page.get("Users", [])

                for user in users:
                    user_count += 1
                    user_name = user["UserName"]
                    user_id = user["UserId"]
                    user_arn = user["Arn"]
                    path = user.get("Path", "/")
                    create_date = user["CreateDate"]
                    password_last_used = user.get("PasswordLastUsed")

                    # Create asset
                    asset = Asset(
                        service="iam",
                        resource_type="iam_user",
                        resource_id=user_id,
                        resource_arn=user_arn,
                        region="global",
                        account_id=connection_info.account_id,
                        name=user_name,
                    )

                    # Store full user data
                    asset.data = {
                        "UserName": user_name,
                        "UserId": user_id,
                        "Arn": user_arn,
                        "Path": path,
                        "CreateDate": create_date.isoformat(),
                        "PasswordLastUsed": (
                            password_last_used.isoformat() if password_last_used else None
                        ),
                    }

                    assets.append(asset)

            self.logger.info(f"Found {user_count} user(s)")

        except Exception as e:
            self.logger.error(f"Failed to list users: {e}")
            raise

        self.logger.info(f"Successfully enumerated {len(assets)} user(s)")
        return assets, findings

    def summarize(self, assets: list[Asset], findings: list[Finding]) -> str:
        """Generate safe summary - NO user names.

        CRITICAL: This summary goes to Claude's context. It must NOT contain
        any user names, ARNs, or other sensitive identifiers.
        """
        if not assets:
            return "No IAM users found in this AWS account."

        # Count users by path (safe to include)
        path_counts: dict[str, int] = {}
        for asset in assets:
            path = asset.data.get("Path", "/") if asset.data else "/"
            path_counts[path] = path_counts.get(path, 0) + 1

        lines = [
            "IAM User Enumeration Complete",
            "",
            f"Discovered {len(assets)} user(s).",
            "",
            "Path distribution:",
        ]

        # Sort by count (descending) for better readability
        for path, count in sorted(path_counts.items(), key=lambda x: -x[1]):
            lines.append(f"  - {path}: {count} user(s)")

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
