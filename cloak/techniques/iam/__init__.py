"""IAM enumeration techniques."""

from cloak.techniques.iam.list_policies import ListPoliciesTechnique
from cloak.techniques.iam.list_roles import ListRolesTechnique
from cloak.techniques.iam.list_users import ListUsersTechnique

__all__ = ["ListUsersTechnique", "ListRolesTechnique", "ListPoliciesTechnique"]

# Technique registry for dynamic loading
TECHNIQUES = {
    "list_users": ListUsersTechnique,
    "list_roles": ListRolesTechnique,
    "list_policies": ListPoliciesTechnique,
}
