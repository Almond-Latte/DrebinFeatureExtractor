import subprocess

import settings
from logger import get_logger
from utils import remove_control_chars, sanitize_to_ascii


def get_net(sample_file: str) -> list[str]:
    """
    Extract network-related entries from the AndroidManifest.xml of an APK.

    Args:
        sample_file (str): Path to the APK file.

    Returns:
        list[str]: A list of network-related entries found in the AndroidManifest.xml.
    """
    logger = get_logger()
    app_net = []

    logger.info("Extracting network data from AndroidManifest.xml")

    try:
        result = subprocess.run(
            [settings.AAPT, "d", "xmltree", sample_file, "AndroidManifest.xml"],
            capture_output=True,
            text=True,
            check=True,
        )
        xml_lines = result.stdout.splitlines()

        logger.debug("-------------------------------------------")
        logger.debug("---------- application network ------------")
        logger.debug("-------------------------------------------")
        for line in xml_lines:
            if "android.net" in line:
                try:
                    net = line.split("=")[1].split('"')[1]
                    # remove control characters
                    net = remove_control_chars(net)
                    if net:
                        app_net.append(sanitize_to_ascii(net))
                        logger.debug(f"Network: {net}")
                except (IndexError, KeyError) as e:
                    logger.error(
                        f"Error reading network data from AndroidManifest.xml: {e}"
                    )
    except subprocess.CalledProcessError as e:
        logger.error(f"Error extracting network data from AndroidManifest.xml: {e}")

    return app_net
