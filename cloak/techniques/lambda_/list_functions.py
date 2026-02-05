"""Lambda list_functions technique - enumerate all Lambda functions."""

from cloak.core.models import Asset, Finding
from cloak.techniques.base import (
    BaseTechnique,
    DryRunResult,
    TechniqueMetadata,
    ValidationResult,
)


class ListFunctionsTechnique(BaseTechnique):
    """Enumerate all Lambda functions across configured regions."""

    @property
    def metadata(self) -> TechniqueMetadata:
        """Return technique metadata."""
        return TechniqueMetadata(
            name="list_functions",
            service="lambda",
            description="Enumerate all Lambda functions with their configuration",
            required_permissions=[
                "lambda:ListFunctions",
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
                f"Call lambda:ListFunctions in {len(regions)} region(s) (paginated API calls)",
            ],
            estimated_api_calls="1-N per region (paginated based on function count)",
            regions=regions,
            required_permissions=self.metadata.required_permissions,
        )

    def _execute_impl(self) -> tuple[list[Asset], list[Finding]]:
        """Execute the function enumeration."""
        assets: list[Asset] = []
        findings: list[Finding] = []

        connection_info = self.validate_connection()
        regions = self.get_regions()

        for region in regions:
            self.logger.info(f"Enumerating Lambda functions in {region}")
            lambda_client = self.get_client("lambda", region_name=region)

            try:
                paginator = lambda_client.get_paginator("list_functions")

                for page in paginator.paginate():
                    self.logger.api_call("lambda:ListFunctions", region=region)
                    functions = page.get("Functions", [])

                    for func in functions:
                        function_name = func["FunctionName"]
                        function_arn = func["FunctionArn"]
                        runtime = func.get("Runtime", "unknown")
                        handler = func.get("Handler", "")
                        code_size = func.get("CodeSize", 0)
                        memory_size = func.get("MemorySize", 128)
                        timeout = func.get("Timeout", 3)
                        last_modified = func.get("LastModified", "")
                        role = func.get("Role", "")
                        description = func.get("Description", "")

                        # Create asset
                        asset = Asset(
                            service="lambda",
                            resource_type="lambda_function",
                            resource_id=function_name,
                            resource_arn=function_arn,
                            region=region,
                            account_id=connection_info.account_id,
                            name=function_name,
                        )

                        # Store full function data
                        asset.data = {
                            "FunctionName": function_name,
                            "FunctionArn": function_arn,
                            "Runtime": runtime,
                            "Handler": handler,
                            "CodeSize": code_size,
                            "MemorySize": memory_size,
                            "Timeout": timeout,
                            "LastModified": last_modified,
                            "Role": role,
                            "Description": description,
                            "CodeSha256": func.get("CodeSha256"),
                            "Version": func.get("Version"),
                            "VpcConfig": func.get("VpcConfig"),
                            "Environment": func.get("Environment"),
                            "TracingConfig": func.get("TracingConfig"),
                            "Layers": func.get("Layers", []),
                            "Architectures": func.get("Architectures", []),
                            "PackageType": func.get("PackageType"),
                        }

                        assets.append(asset)

            except Exception as e:
                self.logger.warning(f"Failed to enumerate functions in {region}: {e}")
                # Continue with other regions
                continue

        self.logger.info(f"Successfully enumerated {len(assets)} function(s)")
        return assets, findings

    def summarize(self, assets: list[Asset], findings: list[Finding]) -> str:
        """Generate safe summary - NO function names.

        CRITICAL: This summary goes to Claude's context. It must NOT contain
        any function names, ARNs, or other sensitive identifiers.
        """
        if not assets:
            return "No Lambda functions found in the configured regions."

        # Count functions by region (safe to include)
        region_counts: dict[str, int] = {}
        for asset in assets:
            region = asset.region or "unknown"
            region_counts[region] = region_counts.get(region, 0) + 1

        # Count functions by runtime (safe to include)
        runtime_counts: dict[str, int] = {}
        for asset in assets:
            runtime = asset.data.get("Runtime", "unknown") if asset.data else "unknown"
            runtime_counts[runtime] = runtime_counts.get(runtime, 0) + 1

        # Calculate total code size
        total_code_size = sum(
            asset.data.get("CodeSize", 0) if asset.data else 0 for asset in assets
        )
        total_code_mb = total_code_size / (1024 * 1024)

        lines = [
            "Lambda Function Enumeration Complete",
            "",
            f"Discovered {len(assets)} function(s) across {len(region_counts)} region(s).",
            "",
            "Region distribution:",
        ]

        # Sort by count (descending) for better readability
        for region, count in sorted(region_counts.items(), key=lambda x: -x[1]):
            lines.append(f"  - {region}: {count} function(s)")

        lines.append("")
        lines.append("Runtime distribution:")
        for runtime, count in sorted(runtime_counts.items(), key=lambda x: -x[1]):
            lines.append(f"  - {runtime}: {count} function(s)")

        lines.append("")
        lines.append(f"Total code size: {total_code_mb:.2f} MB")

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
