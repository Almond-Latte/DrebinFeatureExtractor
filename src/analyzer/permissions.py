import subprocess
from pathlib import Path

import settings
from logger import get_logger
from utils import remove_control_chars


def get_permissions(sample_file: str) -> list[str]:
    """
    Extract the permissions declared in the APK's AndroidManifest.xml.

    Args:
        log_file (str): Path to the log file (currently unused in this implementation).
        sample_file (str): Path to the APK file.

    Returns:
        list[str]: A list of permissions declared in the APK.
    """
    logger = get_logger()
    app_permissions = []

    logger.info("Extracting permissions from AndroidManifest.xml")

    try:
        result = subprocess.run(
            [settings.AAPT, "d", "permissions", sample_file],
            capture_output=True,
            text=True,
            check=True,
        )
        permissions = result.stdout.split("uses-permission: ")

        logger.debug("-------------------------------------------")
        logger.debug("---------- application permissions ---------")
        logger.debug("-------------------------------------------")

        # Skip the first split part as it does not contain a permission
        for permission in permissions[1:]:
            permission = permission.split("\n")[0]
            permission = remove_control_chars(permission)
            if permission:
                app_permissions.append(permission)
                logger.debug(f"Permission: {permission}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error extracting permissions from AndroidManifest.xml: {e}")

    return app_permissions


def check_api_permissions(smali_location: str) -> tuple[list, list]:
    """
    Parse smali files in the given directory and identify permissions required for API calls.

    Args:
        smali_location (str): Path to the directory containing smali files.

    Returns:
        tuple[list, list]:
            - List of unique permissions required by the API calls.
            - List of API calls and their associated permissions.
    """
    logger = get_logger()

    logger.info("Checking API permissions")
    # Read API calls and permissions from the settings file
    api_call_list = []
    try:
        with open(settings.APICALLS, encoding="utf-8") as f:
            api_call_list = [line.strip().split("|") for line in f]
    except FileNotFoundError:
        raise FileNotFoundError("API calls settings file not found.")

    api_permissions = []
    api_calls = []

    # Collect all smali files
    file_list = sorted(Path(smali_location).rglob("*.smali"))

    logger.debug("-------------------------------------------")
    logger.debug("------------ API permissions --------------")
    logger.debug("-------------------------------------------")
    for file_path in file_list:
        try:
            sanitized_file_path = remove_control_chars(str(file_path))
            with open(sanitized_file_path, encoding="utf-8") as smali_file:
                smali_content = smali_file.read()

            for api_call, permission in api_call_list:
                if api_call in smali_content:
                    permission = permission.strip()
                    if permission and permission not in api_permissions:
                        api_permissions.append(permission)
                        logger.debug(f"Permission: {permission}")
                    api_calls.append([api_call, permission])

        except (UnicodeDecodeError, FileNotFoundError):
            logger.error(f"Error reading file {file_path}")

    return api_permissions, api_calls
