import re
from typing import Tuple, List

VERSION_RANGE_SEP = " to "


def is_in_version_range(version: str, version_range: str) -> bool:
    """
    Checks if a provided version matches an affected version or
    is included in an affected version range.
    Versions do not need to be normalized. Eg, could be either 1.5 or 1.5.0
    :param version: version to check
    :param version_range: exact version (1.5, 1.5.0) or range (1.5 to 1.5.6)
    :return: True if version included in version range, False otherwise
    """

    if version_range.find(VERSION_RANGE_SEP) < 0:
        return norm_version(version) == norm_version(version_range)
    else:
        low, high = version_range.split(" to ")
        return True if norm_version(low) <= norm_version(version) <= norm_version(high) else False


def norm_version(version: str) -> Tuple[int, int, int]:
    """
    Normalizes version string, eg, 1.5 is normalized as 1.5.0.
    Raises ValueError if input have unsupported format
    :param version:
    :return: normalized version X.Y.Z as Tuple[X: str, Y: str, Z: str]
    """

    ALL_RELEASES = "all releases prior"

    # handle nasty cases from Istio
    if version.lower().strip() == ALL_RELEASES:
        return 0, 0, 0

    num_dots = version.count('.')
    if num_dots < 1 or num_dots > 2:
        raise ValueError(f'{version} must contain 1 or 2 dots')

    version.strip()
    if num_dots == 1:
        version = f'{version}.0'
    x = re.search("([0-9]+?)\.([0-9]+?)\.([0-9]+)", version)
    if x is not None:
        major = int(x.group(1))
        minor = int(x.group(2))
        build = int(x.group(3))
    else:
        raise ValueError(f'Unable to parse {version}')
    return major, minor, build


def filter_not_applicable_advisories(version: str, advisories: list) -> List[str]:
    """
    Filters a list of security advisories to return those applicable to the provided version
    :param version: version to check
    :param advisories: list of tuples[advisory_link, list[affected_versions]]
    :return: filtered list of applicable advisories list[advisory_link]
    """
    filtered = []
    for adv_link, affected_versions in advisories:
        for affected_version in affected_versions:
            if is_in_version_range(version, affected_version):
                filtered.append(adv_link)
    return filtered
