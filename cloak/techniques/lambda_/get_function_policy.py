"""Lambda get_function_policy technique - get resource-based policies for Lambda functions."""

import json

from cloak.core.config import ParameterSpec
from cloak.core.models import Asset, Finding
from cloak.techniques.base import (
    BaseTechnique,
    DryRunResult,
    TechniqueMetadata,
    ValidationResult,
)


class GetFunctionPolicyTechnique(BaseTechnique):
    """Get resource-based policies for Lambda functions."""

    @property
    def metadata(self) -> TechniqueMetadata:
        """Return technique metadata."""
        return TechniqueMetadata(
            name="get_function_policy",
            service="lambda",
            description="Get resource-based policies for Lambda functions",
            required_permissions=[
                "lambda:ListFunctions",
                "lambda:GetPolicy",
            ],
            required_parameters=[
                ParameterSpec(
                    name="function_name",
                    param_type="str",
                    required=True,
                    description="Name of the function to check, or 'all' to check all functions",
                ),
            ],
            optional_parameters=[],
        )

    def validate(self) -> ValidationResult:
        """Validate configuration."""
        result = ValidationResult(valid=True)

        function_name = self.config.parameters.get("function_name")
        if not function_name:
            result.add_error("function_name parameter is required")
            return result

        if not isinstance(function_name, str):
            result.add_error("function_name must be a string")
            return result

        if function_name.strip() == "":
            result.add_error("function_name cannot be empty")
            return result

        return result

    def dry_run(self) -> DryRunResult:
        """Show planned actions without execution."""
        function_name = self.config.parameters.get("function_name", "unknown")
        regions = self.get_regions()

        if function_name == "all":
            actions = [
                f"Call lambda:ListFunctions in {len(regions)} region(s) (paginated)",
                "Call lambda:GetPolicy for each function (N API calls)",
            ]
            estimated_api_calls = "1-N + N (list functions + get policy for each)"
        else:
            actions = [
                f"Call lambda:GetPolicy for function '{function_name}' in {len(regions)} region(s)",
            ]
            estimated_api_calls = f"{len(regions)} (1 per region)"

        return DryRunResult(
            actions=actions,
            estimated_api_calls=estimated_api_calls,
            regions=regions,
            required_permissions=self.metadata.required_permissions,
        )

    def _execute_impl(self) -> tuple[list[Asset], list[Finding]]:
        """Execute the function policy enumeration."""
        assets: list[Asset] = []
        findings: list[Finding] = []

        connection_info = self.validate_connection()
        regions = self.get_regions()
        function_name = self.config.parameters.get("function_name")

        for region in regions:
            self.logger.info(f"Checking Lambda function policies in {region}")
            lambda_client = self.get_client("lambda", region_name=region)

            # Determine which functions to check
            functions_to_check: list[dict] = []

            if function_name == "all":
                # List all functions first
                try:
                    paginator = lambda_client.get_paginator("list_functions")
                    for page in paginator.paginate():
                        self.logger.api_call("lambda:ListFunctions", region=region)
                        for func in page.get("Functions", []):
                            functions_to_check.append(
                                {
                                    "name": func["FunctionName"],
                                    "arn": func["FunctionArn"],
                                }
                            )
                except Exception as e:
                    self.logger.warning(f"Failed to list functions in {region}: {e}")
                    continue
            else:
                # Check specific function
                functions_to_check.append(
                    {
                        "name": function_name,
                        "arn": f"arn:aws:lambda:{region}:{connection_info.account_id}:function:{function_name}",
                    }
                )

            # Get policy for each function
            for func_info in functions_to_check:
                func_name = func_info["name"]
                func_arn = func_info["arn"]

                try:
                    response = lambda_client.get_policy(FunctionName=func_name)
                    self.logger.api_call("lambda:GetPolicy", function=func_name)

                    # Parse policy JSON
                    policy_text = response.get("Policy", "{}")
                    try:
                        policy_json = json.loads(policy_text)
                    except json.JSONDecodeError as e:
                        self.logger.warning(f"Failed to parse policy JSON for {func_name}: {e}")
                        policy_json = {
                            "error": "Failed to parse policy JSON",
                            "raw_policy": policy_text,
                        }

                    # Create asset
                    asset = Asset(
                        service="lambda",
                        resource_type="lambda_function_policy",
                        resource_id=func_name,
                        resource_arn=func_arn,
                        region=region,
                        account_id=connection_info.account_id,
                        name=func_name,
                    )

                    # Store full policy data
                    asset.data = {
                        "FunctionName": func_name,
                        "FunctionArn": func_arn,
                        "Policy": policy_json,
                        "PolicyText": policy_text,
                        "RevisionId": response.get("RevisionId"),
                    }

                    assets.append(asset)

                except Exception as e:
                    error_msg = str(e)
                    if "ResourceNotFoundException" in error_msg:
                        # Function has no policy - this is normal, not an error
                        self.logger.info(f"Function {func_name} has no resource-based policy")
                        continue
                    elif "ResourceNotFound" in error_msg:
                        # Function doesn't exist in this region
                        self.logger.info(f"Function {func_name} not found in {region}")
                        continue
                    else:
                        self.logger.warning(f"Error getting policy for {func_name}: {e}")
                        continue

        self.logger.info(f"Successfully retrieved {len(assets)} function policy(ies)")
        return assets, findings

    def summarize(self, assets: list[Asset], findings: list[Finding]) -> str:
        """Generate safe summary - NO function names.

        CRITICAL: This summary goes to Claude's context. It must NOT contain
        any function names, ARNs, or other sensitive identifiers.
        """
        function_name = self.config.parameters.get("function_name", "unknown")

        if not assets:
            if function_name == "all":
                return "No Lambda functions with resource-based policies found in the configured regions."
            else:
                return "No resource-based policy found for the specified function, or function not found in the configured regions."

        # Count policies by region (safe to include)
        region_counts: dict[str, int] = {}
        for asset in assets:
            region = asset.region or "unknown"
            region_counts[region] = region_counts.get(region, 0) + 1

        # Count statements in policies
        total_statements = 0
        for asset in assets:
            if asset.data and "Policy" in asset.data:
                policy = asset.data["Policy"]
                if isinstance(policy, dict):
                    total_statements += len(policy.get("Statement", []))

        lines = [
            "Lambda Function Policy Enumeration Complete",
            "",
            f"Discovered {len(assets)} function(s) with resource-based policies.",
            "",
            "Region distribution:",
        ]

        # Sort by count (descending) for better readability
        for region, count in sorted(region_counts.items(), key=lambda x: -x[1]):
            lines.append(f"  - {region}: {count} function(s) with policies")

        lines.append("")
        lines.append(f"Total policy statements: {total_statements}")

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
