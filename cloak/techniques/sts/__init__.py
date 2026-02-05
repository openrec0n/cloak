"""STS enumeration techniques."""

from cloak.techniques.sts.assume_role import AssumeRoleTechnique

__all__ = ["AssumeRoleTechnique"]

# Technique registry for dynamic loading
TECHNIQUES = {
    "assume_role": AssumeRoleTechnique,
}
