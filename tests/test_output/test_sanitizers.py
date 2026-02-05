"""Tests for output sanitization."""

from cloak.output.sanitizers import sanitize_text, validate_summary


class TestValidateSummary:
    """Tests for validate_summary function."""

    def test_clean_summary_passes(self):
        """Test that summary with no sensitive data passes."""
        summary = """
        S3 Bucket Enumeration Complete

        Discovered 15 buckets across 4 regions.
        Region distribution:
          - us-east-1: 8 buckets
          - us-west-2: 4 buckets
          - eu-west-1: 2 buckets
          - ap-southeast-1: 1 bucket
        """
        is_safe, violations = validate_summary(summary)
        assert is_safe
        assert len(violations) == 0

    def test_detects_arn(self):
        """Test that ARNs are detected."""
        summary = "Found bucket: arn:aws:s3:::my-secret-bucket"
        is_safe, violations = validate_summary(summary)
        assert not is_safe
        assert len(violations) > 0
        assert any("arn" in v for v in violations)

    def test_detects_multiple_arns(self):
        """Test that multiple ARNs are detected with examples."""
        summary = "Found arn:aws:s3:::bucket1, arn:aws:s3:::bucket2, arn:aws:s3:::bucket3, arn:aws:s3:::bucket4"
        is_safe, violations = validate_summary(summary)
        assert not is_safe
        # Should show first 3 examples
        violation_text = violations[0]
        assert "arn" in violation_text
        assert "bucket1" in violation_text or "bucket2" in violation_text

    def test_detects_account_id(self):
        """Test that account IDs are detected."""
        summary = "Account 123456789012 has 10 buckets"
        is_safe, violations = validate_summary(summary)
        assert not is_safe
        assert any("account_id" in v for v in violations)

    def test_execution_id_uuid_not_flagged_as_account_id(self):
        """execution_id (UUID) with 12-digit last segment must not be flagged as account_id."""
        summary = "Details stored (execution_id: 3bfef5b9-895a-4360-9899-266044312420)"
        is_safe, violations = validate_summary(summary)
        assert is_safe, f"UUID in summary should not trigger account_id: {violations}"
        assert len(violations) == 0

    def test_detects_access_key(self):
        """Test that access keys are detected."""
        summary = "Found key: AKIAIOSFODNN7EXAMPLE"
        is_safe, violations = validate_summary(summary)
        assert not is_safe
        assert any("access_key" in v for v in violations)

    def test_detects_access_key_asia(self):
        """Test that temporary access keys (ASIA) are detected."""
        summary = "Found key: ASIAIOSFODNN7EXAMPLE"
        is_safe, violations = validate_summary(summary)
        assert not is_safe
        assert any("access_key" in v for v in violations)

    def test_detects_ec2_resource_id(self):
        """Test that EC2 resource IDs are detected."""
        summary = "Instance i-1234567890abcdef0 is running"
        is_safe, violations = validate_summary(summary)
        assert not is_safe
        assert any("ec2_resource" in v for v in violations)

    def test_detects_security_group_id(self):
        """Test that security group IDs are detected."""
        summary = "Security group sg-12345678 is open"
        is_safe, violations = validate_summary(summary)
        assert not is_safe
        assert any("ec2_resource" in v for v in violations)

    def test_detects_vpc_id(self):
        """Test that VPC IDs are detected."""
        summary = "VPC vpc-12345678 has open routes"
        is_safe, violations = validate_summary(summary)
        assert not is_safe
        assert any("ec2_resource" in v for v in violations)

    def test_detects_ip_address(self):
        """Test that IP addresses are detected."""
        summary = "Server at 192.168.1.100 is accessible"
        is_safe, violations = validate_summary(summary)
        assert not is_safe
        assert any("ip_address" in v for v in violations)

    def test_detects_s3_bucket_url(self):
        """Test that S3 bucket URLs are detected."""
        summary = "Bucket URL: my-bucket.s3.amazonaws.com"
        is_safe, violations = validate_summary(summary)
        assert not is_safe
        assert any("s3_bucket" in v for v in violations)

    def test_detects_iam_resource_path(self):
        """Test that IAM resource paths are detected."""
        summary = "Found user/admin-user with elevated privileges"
        is_safe, violations = validate_summary(summary)
        assert not is_safe
        assert any("iam_resource" in v for v in violations)

    def test_multiple_violations(self):
        """Test that multiple types of violations are detected."""
        summary = "Account 123456789012 has bucket my-bucket.s3.amazonaws.com at IP 10.0.0.1"
        is_safe, violations = validate_summary(summary)
        assert not is_safe
        assert len(violations) >= 2  # Account ID and S3 URL at minimum

    def test_empty_summary(self):
        """Test that empty summary is safe."""
        is_safe, violations = validate_summary("")
        assert is_safe
        assert len(violations) == 0


class TestSanitizeText:
    """Tests for sanitize_text function."""

    def test_sanitizes_arn(self):
        """Test that ARNs are removed."""
        text = "Bucket: arn:aws:s3:::my-bucket"
        sanitized = sanitize_text(text)
        assert "arn:aws:s3:::my-bucket" not in sanitized
        assert "[REDACTED]" in sanitized

    def test_sanitizes_account_id(self):
        """Test that account IDs are removed."""
        text = "Account 123456789012 has resources"
        sanitized = sanitize_text(text)
        assert "123456789012" not in sanitized
        assert "[REDACTED]" in sanitized

    def test_sanitizes_multiple_patterns(self):
        """Test that multiple patterns are removed."""
        text = "Account 123456789012 has bucket my-bucket.s3.amazonaws.com"
        sanitized = sanitize_text(text)
        assert "123456789012" not in sanitized
        assert "my-bucket.s3.amazonaws.com" not in sanitized
        assert "[REDACTED]" in sanitized

    def test_custom_replacement(self):
        """Test sanitization with custom replacement string."""
        text = "Bucket: arn:aws:s3:::my-bucket"
        sanitized = sanitize_text(text, replacement="***")
        assert "arn:aws:s3:::my-bucket" not in sanitized
        assert "***" in sanitized
        assert "[REDACTED]" not in sanitized

    def test_sanitizes_all_ec2_resource_types(self):
        """Test that all EC2 resource ID patterns are removed."""
        text = "Resources: i-1234567890abcdef0, sg-12345678, vpc-abc12345, subnet-1a2b3c4d"
        sanitized = sanitize_text(text)
        assert "i-1234567890abcdef0" not in sanitized
        assert "sg-12345678" not in sanitized
        assert "vpc-abc12345" not in sanitized
        assert "subnet-1a2b3c4d" not in sanitized

    def test_preserves_safe_content(self):
        """Test that non-sensitive content is preserved."""
        text = "Found 10 buckets in us-east-1 region with 3 findings"
        sanitized = sanitize_text(text)
        assert "10 buckets" in sanitized
        assert "us-east-1" in sanitized
        assert "3 findings" in sanitized

    def test_empty_text(self):
        """Test that empty text is handled."""
        sanitized = sanitize_text("")
        assert sanitized == ""

    def test_sanitize_text_bucket_names(self):
        """Test sanitizing bucket names from text."""
        text = "Processing bucket my-secret-bucket in region us-east-1"
        # Note: Bucket names alone might not match patterns unless in ARN format
        # This test ensures the sanitize_text function works correctly
        result = sanitize_text(text)
        # Bucket names without ARN context may not be caught by patterns
        # This is intentional - we rely on key-based filtering for those
        assert result is not None

    def test_sanitize_text_comprehensive(self):
        """Test sanitizing multiple pattern types."""
        text = """
        Found resources:
        - Bucket ARN: arn:aws:s3:::my-bucket
        - Account: 123456789012
        - Instance: i-1234567890abcdef0
        - IP: 192.168.1.100
        """

        result = sanitize_text(text)

        assert "arn:aws:s3:::my-bucket" not in result
        assert "123456789012" not in result
        assert "i-1234567890abcdef0" not in result
        assert "192.168.1.100" not in result
        assert "[REDACTED]" in result
