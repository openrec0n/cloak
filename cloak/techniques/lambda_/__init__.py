"""Lambda enumeration techniques."""

from cloak.techniques.lambda_.get_function_policy import GetFunctionPolicyTechnique
from cloak.techniques.lambda_.list_functions import ListFunctionsTechnique

__all__ = [
    "ListFunctionsTechnique",
    "GetFunctionPolicyTechnique",
]

# Technique registry for dynamic loading
TECHNIQUES = {
    "list_functions": ListFunctionsTechnique,
    "get_function_policy": GetFunctionPolicyTechnique,
}
