CC = "".join(map(chr, [*range(0, 32), *range(127, 160)]))  # control characters
CC_TRANS = str.maketrans("", "", CC)


def remove_control_chars(name: str) -> str:
    """
    Remove control characters from a string.

    Args:
        name (str): Input string.

    Returns:
        str: String with control characters removed.
    """

    name = name.translate(CC_TRANS)

    return name


def sanitize_to_ascii(name: str) -> str:
    """
    Sanitize a string to ASCII.

    Args:
        name (str): Input string.

    Returns:
        str: String sanitized to ASCII.
    """

    return name.encode("ascii", "replace").decode()
