import re
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
        manifest = result.stdout

        logger.debug("-------------------------------------------")
        logger.debug("---------- application intents ------------")
        logger.debug("-------------------------------------------")

        # Regular expression to match android:name attributes containing 'intent'
        intent_pattern = re.compile(
            r'A: android:name\(0x01010003\)="([^"]*intent[^"]*)"(?: \(Raw: "([^"]*)"\))?'
        )

        # Find all matches
        matches = intent_pattern.findall(manifest)
        logger.info(f"Found {len(matches)} intents in AndroidManifest.xml")

        for match in matches:
            # If both values are present, use the `Raw` value as it represents the resolved resource.
            intent = match[1] if match[1] else match[0]
            intent = remove_control_chars(intent)
            intent = sanitize_to_ascii(intent)
            app_intents.append(intent)
            logger.debug(f"Intent: {intent}")

        if not app_intents:
            logger.warning("No intents found in the manifest")

    except subprocess.CalledProcessError as e:
        logger.error(f"Error extracting intents from AndroidManifest.xml: {e}")

    return app_intents
