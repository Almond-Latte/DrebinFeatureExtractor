import subprocess

import settings
from logger import get_logger
from utils import remove_control_chars, sanitize_to_ascii


def get_intents(sample_file: str) -> list[str]:
    """
    Extract the intents used by an application from its AndroidManifest.xml.

    Args:
        log_file (str): Path to the log file (currently unused in this implementation).
        sample_file (str): Path to the APK file.

    Returns:
        list[str]: A list of intents used by the application.
    """

    logger = get_logger()

    logger.info("Extracting intents from AndroidManifest.xml")
    app_intents = []

    try:
        result = subprocess.run(
            [settings.AAPT, "d", "xmltree", sample_file, "AndroidManifest.xml"],
            capture_output=True,
            text=True,
            check=True,
        )
        xml_lines = result.stdout.splitlines()

        logger.debug("-------------------------------------------")
        logger.debug("---------- application intents ------------")
        logger.debug("-------------------------------------------")
        for line in xml_lines:
            line = line.strip()
            if line.startswith("E: "):
                # Skip Element nodes
                continue

            if "intent" in line:
                try:
                    intent = line.split("=")[1].split('"')[1]
                    intent = remove_control_chars(intent)
                    logger.debug(f"Intent: {intent}")
                    app_intents.append(sanitize_to_ascii(intent))
                except (IndexError, KeyError) as e:
                    logger.error(f"Error reading intents from AndroidManifest.xml: {e}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error extracting intents from AndroidManifest.xml: {e}")

    return app_intents
