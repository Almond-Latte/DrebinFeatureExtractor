import hashlib
import re
import subprocess
from pathlib import Path

import settings
from logger import get_logger
from utils import remove_control_chars, sanitize_to_ascii


def get_sample_info(sample_file: Path) -> list[str]:
    """
    Extract basic information about the sample APK file.

    Args:
        sample_file (Path): Path to the APK file.

    Returns:
        list[str]: A list of basic information including SHA256, MD5, package name, SDK version, and APK name.
    """
    logger = get_logger()
    logger.info("Extracting basic information from badging")
    logger.debug("-------------------------------------------")
    logger.debug("---------- application information ---------")
    logger.debug("-------------------------------------------")

    # Read file content and calculate hashes
    with open(sample_file, "rb") as fp:
        content = fp.read()
    md5_of_new_job = hashlib.md5(content).hexdigest().upper()
    sha_of_new_job = hashlib.sha256(content).hexdigest().upper()
    logger.info(f"SHA256: {sha_of_new_job}")
    logger.info(f"MD5: {md5_of_new_job}")

    app_infos = [sha_of_new_job, md5_of_new_job]

    try:
        # Run AAPT to get APK information
        result = subprocess.run(
            [settings.AAPT, "d", "badging", sample_file],
            capture_output=True,
            text=True,
            check=False,
        )

        # Handle non-zero return code
        if result.returncode != 0:
            stderr_message = result.stderr.strip()
            if "ERROR getting 'android:icon'" in stderr_message:
                logger.info(
                    f"Ignoring icon-related error for {result.args}: {stderr_message}"
                )
            else:
                logger.error(f"Error running AAPT badging: {stderr_message}")
                raise subprocess.CalledProcessError(
                    result.returncode, result.args, stderr_message
                )

        sample_infos = result.stdout.splitlines()

        # Extract package name
        package_name = "NO_LABEL"
        for line in sample_infos:
            if line.strip().startswith("package: name="):
                parts = line.split("name=")
                if len(parts) > 1:
                    package_name = parts[1].split("'")[1]
                    package_name = remove_control_chars(package_name)
                    package_name = sanitize_to_ascii(package_name)
                break
        logger.debug(f"Package name: {package_name}")
        app_infos.append(package_name)

        # Extract SDK version
        sdk_version = "NO_LABEL"
        for line in sample_infos:
            if line.strip().startswith("sdkVersion"):
                parts = line.split("'")
                if len(parts) > 1:
                    sdk_version = parts[1]
                break
        logger.debug(f"SDK version: {sdk_version}")
        app_infos.append(sdk_version)

        # Append APK name
        apk_name = sample_file.stem
        logger.debug(f"APK name: {apk_name}")
        app_infos.append(apk_name)

    except subprocess.CalledProcessError as e:
        logger.error(f"Error running AAPT badging: {e}")

    return app_infos


def get_activities(sample_file: str) -> list[str]:
    """
    Extract all activities from the APK file. The first activity in the list is the MAIN activity.

    Args:
        sample_file (str): Path to the APK file.

    Returns:
        list[str]: A list of activities used in the APK.

    Info:
        - activities from badging: launchable-activity
        - activities from AndroidManifest.xml: android:name
    """
    logger = get_logger()

    logger.info("Extracting activities from APK badging")
    # Extract activities from AAPT badging
    try:
        result = subprocess.run(
            [settings.AAPT, "dump", "badging", sample_file],
            capture_output=True,
            text=True,
            check=False,
        )

        # Handle non-zero return code
        if result.returncode != 0:
            stderr_message = result.stderr.strip()
            if "ERROR getting 'android:icon'" in stderr_message:
                logger.info(
                    f"Ignoring icon-related error for {result.args}: {stderr_message}"
                )
            else:
                logger.error(f"Error running AAPT badging: {stderr_message}")
                raise subprocess.CalledProcessError(
                    result.returncode, result.args, stderr_message
                )
        manifest = result.stdout

        logger.debug("---------------------------------------------------------")
        logger.debug("---------- application activities from badging ----------")
        logger.debug("---------------------------------------------------------")

        activity_pattern = r"launchable-activity: name='([^']+)'"

        match = re.search(activity_pattern, manifest)
        if match:
            main_activity = match.group(1)
            main_activity = remove_control_chars(main_activity)
            main_activity = sanitize_to_ascii(main_activity)
            logger.debug(f"Main activity: {main_activity}")
        else:
            logger.warning("No launchable activity found in the badging")
            main_activity = ""

    except subprocess.CalledProcessError as e:
        logger.error(f"Error running AAPT badging: {e}")
        return list()

    logger.info("Extracting activities from AndroidManifest.xml")
    # Extract activities from AndroidManifest.xml
    manifest_activities = []
    try:
        result = subprocess.run(
            [settings.AAPT, "d", "xmltree", sample_file, "AndroidManifest.xml"],
            capture_output=True,
            text=True,
            check=True,
        )
        manifest = result.stdout

        logger.debug("----------------------------------------------------------")
        logger.debug("---------- application activities from manifest ----------")
        logger.debug("----------------------------------------------------------")

        # Extract activity blocks
        activity_block_pattern = r"E: activity.*?(?=E: |\Z)"
        activity_blocks = re.findall(activity_block_pattern, manifest, re.DOTALL)
        logger.info(f"Found {len(activity_blocks)} activity blocks")

        # Extract activity names

        # Regular expression to extract the value of the `android:name` attribute and its optional `Raw` value.

        # Match the `android:name` attribute.
        # Example: A: android:name(0x01010003)="com.example.MyActivity"
        # - Captures the value in the first group: "com.example.MyActivity".
        activity_name_pattern = re.compile(
            r'A: android:name\(0x01010003\)="([^"]+)"'  # Capture the `android:name` value.
            r'(?: \(Raw: "([^"]+)"\))?'  # Optionally capture the `Raw` value if present.
        )
        for block in activity_blocks:
            match = activity_name_pattern.search(block)
            if match:
                # If both values are present, use the `Raw` value as it represents the resolved resource.
                activity = match.group(2) if match.group(2) else match.group(1)
                activity = remove_control_chars(activity)
                activity = sanitize_to_ascii(activity)
                manifest_activities.append(activity)
                logger.debug(f"Activity: {activity}")

        if len(manifest_activities) != len(activity_blocks):
            logger.warning("Mismatch between activity blocks and extracted activities")

    except subprocess.CalledProcessError as e:
        logger.error(f"Error extracting activities from AndroidManifest.xml: {e}")
    return (
        [main_activity] + manifest_activities if main_activity else manifest_activities
    )


def get_providers(sample_file: str) -> list[str]:
    """
    Extract the providers declared in the APK's AndroidManifest.xml.

    Args:
        log_file (str): Path to the log file (currently unused in this implementation).
        sample_file (str): Path to the APK file.

    Returns:
        list[str]: A list of providers declared in the APK.
    """
    logger = get_logger()
    app_providers = []
    logger.info("Extracting providers from AndroidManifest.xml")

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
        logger.debug("---------- application providers ----------")
        logger.debug("-------------------------------------------")

        # Regular expression to find provider blocks
        provider_block_pattern = re.compile(r"E: provider.*?(?=E: |\Z)", re.DOTALL)
        provider_blocks = provider_block_pattern.findall(manifest)
        logger.info(f"Found {len(provider_blocks)} provider blocks")

        # Regular expression to find android:name inside the provider block

        provider_name_pattern = re.compile(
            r'A: android:name\(0x01010003\)="([^"]+)"'  # Capture the `android:name` value.
            r'(?: \(Raw: "([^"]+)"\))?'  # Optionally capture the `Raw` value if present.
        )

        for block in provider_blocks:
            match = provider_name_pattern.search(block)
            if match:
                # If both values are present, use the `Raw` value as it represents the resolved resource.
                provider_name = match.group(2) if match.group(2) else match.group(1)
                sanitized_provider = sanitize_to_ascii(
                    remove_control_chars(provider_name)
                )
                if sanitized_provider:
                    app_providers.append(sanitized_provider)
                    logger.debug(f"Provider: {sanitized_provider}")

        if len(app_providers) != len(provider_blocks):
            logger.warning("Mismatch between provider blocks and extracted providers")
            logger.warning(f"number of found provider blocks: {len(provider_blocks)}")
            logger.warning(f"number of found provider names: {len(app_providers)}")

    except subprocess.CalledProcessError as e:
        logger.error(f"Error extracting providers from {sample_file}: {e}")

    return app_providers


def get_services_receivers(sample_file: str) -> list[str]:
    """
    Extract services and receivers declared in the APK's AndroidManifest.xml.

    Args:
        log_file (str): Path to the log file (currently unused in this implementation).
        sample_file (str): Path to the APK file.

    Returns:
        list[str]: A list of services and receivers declared in the APK.
    """
    logger = get_logger()
    services_and_receivers = []

    logger.info("Extracting services and receivers from AndroidManifest.xml")
    try:
        # Run the aapt command to dump the AndroidManifest.xml
        result = subprocess.run(
            [settings.AAPT, "d", "xmltree", sample_file, "AndroidManifest.xml"],
            capture_output=True,
            text=True,
            check=True,
        )
        manifest = result.stdout

        logger.debug("----------------------------------------------")
        logger.debug("----- application services and receivers -----")
        logger.debug("----------------------------------------------")

        # Regular expression to extract service or receiver blocks
        block_pattern = re.compile(r"E: (?:service|receiver).*?(?=E: |\Z)", re.DOTALL)
        # Regular expression to extract android:name attribute within a block
        name_pattern = re.compile(
            r'A: android:name\(0x01010003\)="([^"]+)"'  # Capture the `android:name` value.
            r'(?: \(Raw: "([^"]+)"\))?'  # Optionally capture the `Raw` value if present.
        )

        # Find all service and receiver blocks
        blocks = block_pattern.findall(manifest)
        logger.info(f"Found {len(blocks)} service and receiver blocks")

        for block in blocks:
            # Search for android:name within the block
            match = name_pattern.search(block)
            if match:
                # If both values are present, use the `Raw` value as it represents the resolved resource.
                name = match.group(1) if match.group(2) else match.group(1)
                name = sanitize_to_ascii(remove_control_chars(name))
                if name and name not in services_and_receivers:
                    services_and_receivers.append(name)
                    logger.debug(f"Found {name}")

        if len(services_and_receivers) != len(blocks):
            logger.warning(
                "Mismatch between service/receiver blocks and extracted services/receivers"
            )
            logger.warning(f"number of found service/receiver blocks: {len(blocks)}")
            logger.warning(
                f"number of found service/receiver names: {len(services_and_receivers)}"
            )

    except subprocess.CalledProcessError as e:
        logger.error(f"Error extracting services and receivers from {sample_file}: {e}")

    return services_and_receivers


def get_files_inside_apk(sample_file: str) -> list[str]:
    """
    Get a list of files inside an APK file.

    Args:
        sample_file (str): Path to the APK file.

    Returns:
        list[str]: A list of file names inside the APK file.
    """
    logger = get_logger()
    app_files = []

    logger.info("Extracting files from APK")
    try:
        result = subprocess.run(
            [settings.AAPT, "list", sample_file],
            capture_output=True,
            text=True,
            check=True,
        )
        xml_lines = result.stdout.splitlines()

        logger.debug("-------------------------------------------")
        logger.debug("---------- application files --------------")
        logger.debug("-------------------------------------------")

        for line in xml_lines:
            file_name = line.strip()
            file_name = remove_control_chars(file_name)
            if file_name:
                app_files.append(sanitize_to_ascii(file_name))
                # logger.debug(f"File: {file_name}")

        logger.info(f"Found {len(app_files)} files in the APK")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error extracting files from APK: {e}")

    return app_files
