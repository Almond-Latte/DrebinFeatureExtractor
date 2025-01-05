import subprocess

import settings
from logger import get_logger
from utils import remove_control_chars, sanitize_to_ascii


def get_features(sample_file: str) -> list[str]:
    """
    Extract the features used by an application from its APK file.

    Args:
        sample_file (str): Path to the APK file.

    Returns:
        list[str]: A list of unique features used by the application.

    Info:
        uses-feature elements are used to specify the features that the application requires.
        should uses-implied-feature be considered as well?
    """
    logger = get_logger()
    logger.info("Extracting features from badging")
    logger.debug("-------------------------------------------")
    logger.debug("---------- application features -----------")
    logger.debug("-------------------------------------------")
    app_features = set()

    try:
        # Run AAPT command to get APK information
        result = subprocess.run(
            [settings.AAPT, "d", "badging", sample_file],
            capture_output=True,
            text=True,
            check=True,
        )
        sample_infos = result.stdout.splitlines()

        # Extract features from lines starting with "uses-feature"
        for line in sample_infos:
            if line.strip().startswith("uses-feature"):
                try:
                    # Extract the feature name between single quotes
                    feature = line.split("'")[1]
                    # Sanitize and add to the set
                    sanitized_feature = sanitize_to_ascii(remove_control_chars(feature))
                    if sanitized_feature:
                        app_features.add(sanitized_feature)
                        logger.debug(f"Feature: {sanitized_feature}")
                except IndexError:
                    logger.warning(f"Malformed feature line: {line.strip()}")

    except subprocess.CalledProcessError as e:
        logger.error(f"Error extracting features from {sample_file}: {e}")

    return sorted(app_features)  # Convert set to sorted list
