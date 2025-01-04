import subprocess

import settings
from logger import get_logger
from utils import remove_control_chars, sanitize_to_ascii


def get_features(sample_file: str) -> list[str]:
    """
    Extract the features used by an application from its APK file.

    Args:
        log_file (str): Path to the log file (currently unused in this implementation).
        sample_file (str): Path to the APK file.

    Returns:
        list[str]: A list of unique features used by the application.
    """
    logger = get_logger()
    app_features = []

    logger.info("Extracting features from badging")

    try:
        result = subprocess.run(
            [settings.AAPT, "d", "badging", sample_file],
            capture_output=True,
            text=True,
            check=True,
        )
        sample_infos = result.stdout.splitlines()

        logger.debug("-------------------------------------------")
        logger.debug("---------- application features -----------")
        logger.debug("-------------------------------------------")
        for sample_info in sample_infos:
            sample_info = sample_info.strip()
            if sample_info.startswith("uses-feature"):
                try:
                    sample_feature = sample_info.split("'")[1]
                    sample_feature = remove_control_chars(sample_feature)
                    if sample_feature and sample_feature not in app_features:
                        app_features.append(sanitize_to_ascii(sample_feature))
                        logger.debug(f"Feature: {sample_feature}")
                except IndexError:
                    continue
    except subprocess.CalledProcessError as e:
        logger.error(f"Error extracting features from {sample_file}: {e}")

    return app_features
