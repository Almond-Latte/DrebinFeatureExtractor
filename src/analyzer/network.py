import re
import subprocess

import settings
from logger import get_logger
from utils import remove_control_chars, sanitize_to_ascii


def get_net(sample_file: str) -> list[str]:
    """
    Extract all occurrences of 'android.net' references from the APK's AndroidManifest.xml.

    Args:
        sample_file (str): Path to the APK file.

    Returns:
        list[str]: A list of strings containing 'android.net' references.
    """
    logger = get_logger()
    android_net_references = []

    logger.info("Extracting 'android.net' references from AndroidManifest.xml")

    try:
        # Run aapt command to extract AndroidManifest.xml
        result = subprocess.run(
            [settings.AAPT, "d", "xmltree", sample_file, "AndroidManifest.xml"],
            capture_output=True,
            text=True,
            check=True,
        )
        manifest = result.stdout

        logger.debug("-------------------------------------------")
        logger.debug("---------- application network ------------")
        logger.debug("-------------------------------------------")

        # Regular expression to find android.net references

        # Match the `android:name` attribute.
        # Example: A: android:name(0x01010003)="android.net.conn.CONNECTIVITY_CHANGE"
        # - Captures the value in the first group: "conn.CONNECTIVITY_CHANGE"
        android_net_pattern = re.compile(
            r'A: android:name\(0x01010003\)="([^"]+)"'  # Capture the `android:name` value.
            r'(?: \(Raw: "([^"]+)"\))?'  # Optionally capture the `Raw` value if present.
        )

        # Find all occurrences of 'android.net'
        matches = android_net_pattern.findall(manifest)

        for match in matches:
            android_name = match[0]
            raw_value = match[1]

            # If both values are present, use the `Raw` value as it represents the resolved resource.
            if "android.net" in raw_value:
                resolved_value = raw_value
            elif "android.net" in android_name:
                resolved_value = android_name
            else:
                continue

            resolved_value = remove_control_chars(resolved_value)
            resolved_value = sanitize_to_ascii(resolved_value)
            android_net_references.append(resolved_value)
            logger.debug(f"Network: {resolved_value}")

        if not android_net_references:
            logger.info("No 'android.net' references found in the manifest")

    except subprocess.CalledProcessError as e:
        logger.error(
            f"Error extracting 'android.net' references from {sample_file}: {e}"
        )

    return android_net_references
