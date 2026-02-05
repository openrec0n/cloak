"""STS assume_role technique - assume an IAM role and obtain temporary credentials."""

import re
import uuid

from cloak.core.config import ParameterSpec
from cloak.core.models import Asset, Finding
from cloak.techniques.base import (
    BaseTechnique,
    DryRunResult,
    TechniqueMetadata,
    ValidationResult,
)


class AssumeRoleTechnique(BaseTechnique):
    """Assume an IAM role and obtain temporary security credentials.

    This technique calls AWS STS AssumeRole to obtain temporary credentials
    for the specified IAM role. Credentials are stored securely in the database
    and can be retrieved using --execution-info <id>.

    SECURITY NOTE: Temporary credentials are stored in the database but NEVER
    appear in the summary returned to Claude's context.
    """

    # Valid ARN pattern for IAM roles
    ARN_PATTERN = re.compile(r"^arn:aws:iam::\d{12}:role/.+$")

    # Session name pattern (AWS constraint)
    SESSION_NAME_PATTERN = re.compile(r"^[\w+=,.@-]{2,64}$")

    # Duration constraints (AWS limits)
    MIN_DURATION_SECONDS = 900  # 15 minutes
    MAX_DURATION_SECONDS = 43200  # 12 hours
    DEFAULT_DURATION_SECONDS = 3600  # 1 hour

    @property
    def metadata(self) -> TechniqueMetadata:
        """Return technique metadata."""
        return TechniqueMetadata(
            name="assume_role",
            service="sts",
            description="Assume an IAM role and obtain temporary security credentials",
            required_permissions=[
                "sts:AssumeRole",
            ],
            required_parameters=[
                ParameterSpec(
                    name="role_arn",
                    param_type="str",
                    required=True,
                    description="Full ARN of the IAM role to assume",
                ),
            ],
            optional_parameters=[
                ParameterSpec(
                    name="session_name",
                    param_type="str",
                    required=False,
                    default=None,
                    description="Identifier for the assumed role session (2-64 chars)",
                ),
                ParameterSpec(
                    name="duration_seconds",
                    param_type="int",
                    required=False,
                    default=3600,
                    description="Session duration in seconds (900-43200)",
                ),
                ParameterSpec(
                    name="external_id",
                    param_type="str",
                    required=False,
                    default=None,
                    description="External ID for cross-account role assumption",
                ),
            ],
        )

    def validate(self) -> ValidationResult:
        """Validate configuration parameters.

        Checks:
        - role_arn is provided and has valid ARN format
        - duration_seconds is within AWS limits (900-43200)
        - session_name matches AWS naming constraints if provided
        """
        result = ValidationResult(valid=True)

        # Validate role_arn (required)
        role_arn = self.config.parameters.get("role_arn")
        if not role_arn:
            result.add_error("role_arn parameter is required")
            return result

        if not self.ARN_PATTERN.match(role_arn):
            result.add_error(
                "role_arn must be a valid IAM role ARN "
                "(format: arn:aws:iam::<account-id>:role/<role-name>)"
            )

        # Validate duration_seconds (optional)
        duration = self.config.parameters.get("duration_seconds", self.DEFAULT_DURATION_SECONDS)
        if not isinstance(duration, int):
            result.add_error("duration_seconds must be an integer")
        elif not (self.MIN_DURATION_SECONDS <= duration <= self.MAX_DURATION_SECONDS):
            result.add_error(
                f"duration_seconds must be between {self.MIN_DURATION_SECONDS} "
                f"and {self.MAX_DURATION_SECONDS}"
            )

        # Validate session_name (optional)
        session_name = self.config.parameters.get("session_name")
        if session_name is not None and not self.SESSION_NAME_PATTERN.match(session_name):
            result.add_error(
                "session_name must be 2-64 characters and contain only "
                "alphanumeric characters, =,.@-_"
            )

        return result

    def dry_run(self) -> DryRunResult:
        """Show planned actions without execution."""
        role_arn = self.config.parameters.get("role_arn", "<role_arn>")
        duration = self.config.parameters.get("duration_seconds", self.DEFAULT_DURATION_SECONDS)
        external_id = self.config.parameters.get("external_id")

        actions = [
            f"Call sts:AssumeRole for role: {role_arn}",
            f"Request session duration: {duration} seconds",
        ]

        if external_id:
            actions.append("Include external ID for cross-account trust")

        warnings = []
        if duration > 3600:
            warnings.append(
                f"Session duration ({duration}s) exceeds default 1 hour. "
                "Ensure the role's MaxSessionDuration allows this."
            )

        return DryRunResult(
            actions=actions,
            estimated_api_calls="1",
            regions=["global"],
            required_permissions=self.metadata.required_permissions,
            warnings=warnings,
        )

    def _execute_impl(self) -> tuple[list[Asset], list[Finding]]:
        """Execute the role assumption."""
        assets: list[Asset] = []
        findings: list[Finding] = []

        # Get STS client (STS is a global service)
        sts_client = self.get_client("sts")
        connection_info = self.validate_connection()

        # Get parameters
        role_arn = self.config.parameters["role_arn"]
        session_name = self.config.parameters.get("session_name", f"cloak-{uuid.uuid4().hex[:8]}")
        duration = self.config.parameters.get("duration_seconds", self.DEFAULT_DURATION_SECONDS)
        external_id = self.config.parameters.get("external_id")

        # Build request parameters
        params: dict = {
            "RoleArn": role_arn,
            "RoleSessionName": session_name,
            "DurationSeconds": duration,
        }

        if external_id:
            params["ExternalId"] = external_id

        self.logger.info(f"Assuming role with session name: {session_name}")

        try:
            self.logger.api_call("sts:AssumeRole")
            response = sts_client.assume_role(**params)

            # Extract response data
            credentials = response["Credentials"]
            assumed_role_user = response["AssumedRoleUser"]

            # Create asset for the assumed role session
            asset = Asset(
                service="sts",
                resource_type="assumed_role_session",
                resource_id=assumed_role_user["AssumedRoleId"],
                resource_arn=assumed_role_user["Arn"],
                region="global",
                account_id=connection_info.account_id,
                name=session_name,
            )

            # Store full response data including credentials
            # SECURITY NOTE: Credentials are stored in the database but
            # NEVER included in the summary returned to Claude
            asset.data = {
                "Credentials": {
                    "AccessKeyId": credentials["AccessKeyId"],
                    "SecretAccessKey": credentials["SecretAccessKey"],
                    "SessionToken": credentials["SessionToken"],
                    "Expiration": credentials["Expiration"].isoformat(),
                },
                "AssumedRoleUser": {
                    "AssumedRoleId": assumed_role_user["AssumedRoleId"],
                    "Arn": assumed_role_user["Arn"],
                },
                "PackedPolicySize": response.get("PackedPolicySize"),
                "SourceIdentity": response.get("SourceIdentity"),
                "RequestedDuration": duration,
                "SessionName": session_name,
            }

            assets.append(asset)

            self.logger.info("Successfully assumed role")

        except Exception as e:
            self.logger.error(f"Failed to assume role: {e}")
            raise

        return assets, findings

    def summarize(self, assets: list[Asset], findings: list[Finding]) -> str:
        """Generate safe summary - NO credentials or sensitive identifiers.

        CRITICAL: This summary goes to Claude's context. It must NOT contain
        any credentials (AccessKeyId, SecretAccessKey, SessionToken),
        role ARNs, account IDs, or other sensitive identifiers.
        """
        if not assets:
            return "Failed to assume role. No credentials obtained."

        asset = assets[0]
        data = asset.data or {}

        # Extract safe metadata only
        expiration = data.get("Credentials", {}).get("Expiration", "unknown")
        duration = data.get("RequestedDuration", self.DEFAULT_DURATION_SECONDS)
        session_name = data.get("SessionName", "unknown")

        lines = [
            "IAM Role Assumption Complete",
            "",
            "Successfully assumed role.",
            "Session details:",
            f"  - Session Name: {session_name}",
            f"  - Expires: {expiration}",
            f"  - Duration: {duration} seconds",
            "",
            "Credentials stored securely in database.",
            "Use --execution-info <id> to retrieve credentials.",
            "",
            f"Full details stored in database (execution_id: {self.execution_id})",
        ]

        if findings:
            lines.insert(-1, "")
            lines.insert(-1, f"Findings: {len(findings)} issue(s) detected")

        return "\n".join(lines)
