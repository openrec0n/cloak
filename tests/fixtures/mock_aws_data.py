"""Mock AWS data for testing."""

import boto3


def create_mock_s3_buckets(region="us-east-1", count=3):
    """Create mock S3 buckets for testing.

    Args:
        region: AWS region to create buckets in
        count: Number of buckets to create

    Returns:
        List of bucket names created
    """
    s3 = boto3.client("s3", region_name=region)
    bucket_names = []

    for i in range(count):
        bucket_name = f"test-bucket-{i+1}"
        if region == "us-east-1":
            s3.create_bucket(Bucket=bucket_name)
        else:
            s3.create_bucket(
                Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region}
            )
        bucket_names.append(bucket_name)

    return bucket_names


def create_mock_s3_buckets_multiregion():
    """Create mock S3 buckets across multiple regions.

    Returns:
        Dict mapping region names to lists of bucket names
    """
    buckets_by_region = {}

    # US East
    buckets_by_region["us-east-1"] = create_mock_s3_buckets("us-east-1", 2)

    # US West
    buckets_by_region["us-west-2"] = create_mock_s3_buckets("us-west-2", 1)

    # EU
    buckets_by_region["eu-west-1"] = create_mock_s3_buckets("eu-west-1", 1)

    return buckets_by_region
