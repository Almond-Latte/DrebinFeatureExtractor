import hashlib
import subprocess

import settings
from logger import get_logger
from utils import remove_control_chars, sanitize_to_ascii


def get_sample_info(sample_file: str) -> list[str]:
    """
    Extract basic information about the sample APK file.

    Args:
        log_file (str): Path to the log file (currently unused in this implementation).
        sample_file (str): Path to the APK file.

    Returns:
        list[str]: A list of basic information including SHA256, MD5, package name, SDK version, and APK name.
    """
    global sha
    logger = get_logger()

    # Read file content and calculate hashes
    with open(sample_file, "rb") as fp:
        content = fp.read()
    md5_of_new_job = hashlib.md5(content).hexdigest().upper()
    sha_of_new_job = hashlib.sha256(content).hexdigest().upper()
    sha = sha_of_new_job

    app_infos = [sha_of_new_job, md5_of_new_job]

    logger.info(f"SHA256: {sha_of_new_job}")
    logger.info(f"MD5: {md5_of_new_job}")

    logger.info("Extracting basic information from badging")

    try:
        # Run AAPT to get APK information
        result = subprocess.run(
            [settings.AAPT, "d", "badging", sample_file],
            capture_output=True,
            text=True,
            check=True,
        )
        sample_infos = result.stdout.splitlines()

        logger.debug("-------------------------------------------")
        logger.debug("---------- application information ---------")
        logger.debug("-------------------------------------------")
        # Extract package name
        package_name = next(
            (
                line.split("name=")[1].split("'")[1]
                for line in sample_infos
                if line.strip().startswith("package: name=")
            ),
            "NO_LABEL",
        )
        app_infos.append(sanitize_to_ascii(package_name))
        logger.debug(f"Package name: {package_name}")

        # Extract SDK version
        sdk_version = next(
            (
                line.split("'")[1]
                for line in sample_infos
                if line.strip().startswith("sdkVersion")
            ),
            "0",
        )
        app_infos.append(sdk_version)
        logger.debug(f"SDK version: {sdk_version}")

        # Append APK name
        apk_name = sample_file.split("/")[-1]
        app_infos.append(sanitize_to_ascii(apk_name))
        logger.debug(f"APK name: {apk_name}")

    except subprocess.CalledProcessError as e:
        logger.error(f"Error running AAPT: {e}")

    return app_infos


def get_activities(sample_file: str) -> list[str]:
    """
    Extract all activities from the APK file. The first activity in the list is the MAIN activity.

    Args:
        sample_file (str): Path to the APK file.

    Returns:
        list[str]: A list of activities used in the APK.
    """
    logger = get_logger()
    activities = []

    logger.info("Extracting activities from APK badging")
    # Extract activities from AAPT badging
    try:
        result = subprocess.run(
            [settings.AAPT, "dump", "badging", sample_file],
            capture_output=True,
            text=True,
            check=True,
        )
        manifest = result.stdout.splitlines()

        logger.debug("--------------------------------------------")
        logger.debug("---------- application activities ----------")
        logger.debug("--------------------------------------------")
        for line in manifest:
            if "activity" in line:
                try:
                    activity = line.split("'")[1].split(".")[-1]
                    activity = remove_control_chars(activity)
                    activity = "." + activity
                    activities.append(sanitize_to_ascii(activity))
                    logger.debug(f"Activity: {activity}")
                except IndexError as e:
                    logger.error(f"Error extracting activities from AAPT badging: {e}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running AAPT badging: {e}")
        return activities

    logger.info("Extracting activities from AndroidManifest.xml")
    # Extract activities from AndroidManifest.xml
    try:
        result = subprocess.run(
            [settings.AAPT, "d", "xmltree", sample_file, "AndroidManifest.xml"],
            capture_output=True,
            text=True,
            check=True,
        )
        manifest_lines = result.stdout.splitlines()

        logger.debug("--------------------------------------------")
        logger.debug("---------- application activities ----------")
        logger.debug("--------------------------------------------")

        for i, line in enumerate(manifest_lines):
            # search for activity tag
            if "E: activity" in line.strip():
                try:
                    if "Raw" not in manifest_lines[i + 1]:
                        next_line = manifest_lines[i + 2].split("=")[1].split('"')[1]
                    else:
                        next_line = manifest_lines[i + 1].split("=")[1].split('"')[1]

                    next_line = remove_control_chars(next_line)
                    if next_line not in activities and next_line:
                        activities.append(sanitize_to_ascii(next_line))
                        logger.debug(f"Activity: {next_line}")
                except (IndexError, KeyError) as e:
                    logger.error(
                        f"Error extracting activities from AndroidManifest.xml: {e}"
                    )
    except subprocess.CalledProcessError as e:
        logger.error(f"Error extracting activities from AndroidManifest.xml: {e}")
    return activities


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
        result = subprocess.run(
            [settings.AAPT, "d", "xmltree", sample_file, "AndroidManifest.xml"],
            capture_output=True,
            text=True,
            check=True,
        )
        xml_lines = result.stdout.splitlines()

        logger.debug("-------------------------------------------")
        logger.debug("---------- application providers ----------")
        logger.debug("-------------------------------------------")

        for line in xml_lines:
            if "provider" in line:
                try:
                    provider = line.split("=")[1].split('"')[1]
                    # remove control characters
                    provider = remove_control_chars(provider)
                    if provider:
                        app_providers.append(sanitize_to_ascii(provider))
                        logger.debug(f"Provider: {provider}")
                except (IndexError, KeyError):
                    continue
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
        result = subprocess.run(
            [settings.AAPT, "d", "xmltree", sample_file, "AndroidManifest.xml"],
            capture_output=True,
            text=True,
            check=True,
        )
        manifest_lines = result.stdout.splitlines()

        logger.debug("----------------------------------------------")
        logger.debug("----- application services and receivers -----")
        logger.debug("----------------------------------------------")

        # Extract services
        for i, line in enumerate(manifest_lines):
            # search for service tag
            if "E: service" in line.strip():
                try:
                    next_line = manifest_lines[i + 1].split("=")[1].split('"')[1]
                    next_line = remove_control_chars(next_line)
                    if next_line and next_line not in services_and_receivers:
                        services_and_receivers.append(sanitize_to_ascii(next_line))
                        logger.debug(f"Service: {next_line}")
                except (IndexError, KeyError) as e:
                    logger.error(f"Error extracting services from {sample_file}: {e}")

        # Extract receivers
        for i, line in enumerate(manifest_lines):
            if "E: receiver" in line:
                try:
                    next_line = manifest_lines[i + 1].split("=")[1].split('"')[1]
                    # remove control characters
                    next_line = remove_control_chars(next_line)
                    if next_line and next_line not in services_and_receivers:
                        services_and_receivers.append(sanitize_to_ascii(next_line))
                        logger.debug(f"Receiver: {next_line}")
                except (IndexError, KeyError) as e:
                    logger.error(f"Error extracting receivers from {sample_file}: {e}")

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
    except subprocess.CalledProcessError as e:
        logger.error(f"Error extracting files from APK: {e}")

    return app_files
