import re


WINDOWS_ABSOLUTE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])(?:[A-Z]:[\\/]|\\\\[^\\/\s]+[\\/])"
)
POSIX_ABSOLUTE = re.compile(
    r"(?<![:/A-Za-z0-9._-])/(?!/)[^\s`'\"<>]+"
)
PATH_PLACEHOLDER_SEGMENT = re.compile(
    r"(?<=[/\\])<[A-Za-z][A-Za-z0-9._-]*>(?=[/\\])"
)
KNOWN_LOCAL_LITERAL_HASHES = (
    "bdc1db0bccf4d5125ebd25c5b23a7d157d6b54468d4b699bb04c720f0db09649",
)


def contains_absolute_path(text):
    masked = PATH_PLACEHOLDER_SEGMENT.sub("placeholder", text)
    return bool(
        WINDOWS_ABSOLUTE.search(masked) or POSIX_ABSOLUTE.search(masked)
    )
