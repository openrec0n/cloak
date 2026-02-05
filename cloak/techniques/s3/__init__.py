"""S3 enumeration techniques."""

from cloak.techniques.s3.get_bucket_acl import GetBucketAclTechnique
from cloak.techniques.s3.get_bucket_policy import GetBucketPolicyTechnique
from cloak.techniques.s3.list_buckets import ListBucketsTechnique

__all__ = ["ListBucketsTechnique", "GetBucketAclTechnique", "GetBucketPolicyTechnique"]

# Technique registry for dynamic loading
TECHNIQUES = {
    "list_buckets": ListBucketsTechnique,
    "get_bucket_acl": GetBucketAclTechnique,
    "get_bucket_policy": GetBucketPolicyTechnique,
}
