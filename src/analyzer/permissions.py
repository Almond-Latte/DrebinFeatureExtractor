import re
import subprocess
from pathlib import Path

import settings
from logger import get_logger
from utils import remove_control_chars, sanitize_to_ascii


def get_permissions(sample_file: str) -> list[str]:
    """
    Extract the permissions declared in the APK's AndroidManifest.xml.

    Args:
        sample_file (str): Path to the APK file.

    Returns:
        list[str]: A list of permissions declared in the APK.
    """
    logger = get_logger()
    app_permissions = []

    logger.info("Extracting permissions from AndroidManifest.xml")

    try:
        # Run aapt to extract permissions
        result = subprocess.run(
            [settings.AAPT, "d", "permissions", sample_file],
            capture_output=True,
            text=True,
            check=True,
        )
        output = result.stdout

        logger.debug("-------------------------------------------")
        logger.debug("---------- application permissions --------")
        logger.debug("-------------------------------------------")

        # Regular expression to extract 'name' values from 'uses-permission'
        permission_pattern = re.compile(r"uses-permission: name='([^']+)'")
        matches = permission_pattern.findall(output)
        logger.info(f"Found {len(matches)} uses-permissions in AndroidManifest.xml")

        for permission in matches:
            sanitized_permission = sanitize_to_ascii(remove_control_chars(permission))
            app_permissions.append(sanitized_permission)
            logger.debug(f"uses-permission: {sanitized_permission}")

        if not app_permissions:
            logger.warning("No permissions found in the manifest")

    except subprocess.CalledProcessError as e:
        logger.error(f"Error extracting permissions from {sample_file}: {e}")

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

    api_permissions = set()
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
                        api_permissions.add(permission)
                        logger.debug(f"api-permission: {permission}")
                    api_calls.append([api_call, permission])

        except (UnicodeDecodeError, FileNotFoundError) as e:
            logger.error(f"Error reading {file_path}: {e}")

    return list(api_permissions), api_calls
