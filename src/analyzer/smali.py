import csv
import os
import re
import subprocess
from pathlib import Path

import settings
from logger import get_logger


def dex2x(tmp_dir: str, dex_file: str) -> str:
    """
    Disassemble a dex file into smali code using baksmali.

    Args:
        tmp_dir (str): Temporary directory for the disassembled files.
        dex_file (str): Path to the dex file to disassemble.

    Returns:
        str: Path to the directory containing the disassembled smali code.
    """
    logger = get_logger()

    logger.info("Disassembling dex file using baksmali")

    smali_location = Path(tmp_dir) / "smali"
    smali_location.mkdir(parents=True, exist_ok=True)

    try:
        subprocess.run(
            [
                "java",
                "-Xmx256M",
                "-jar",
                settings.BAKSMALI,
                "disassemble",
                "-o",
                str(smali_location),
                dex_file,
            ],
            check=True,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        logger.error(f"Error disassembling dex file: {e}")
        raise

    return str(smali_location)


def parse_smali_calls(smali_location: str) -> list[str]:
    """
    Parse smali output for potentially suspicious API calls.

    Args:
        smali_location (str): Path to the directory containing smali files.

    Returns:
        list[str]: A list of potentially suspicious API calls found in the smali files.
    """
    logger = get_logger()
    dangerous_calls = []
    dangerous_patterns = {
        "Cipher": "Cipher({prev_line})",
        "crypto": None,
        "Ljava/net/HttpURLconnection;->setRequestMethod(Ljava/lang/String;)": "HTTP GET/POST",
        "Ljava/net/HttpURLconnection": "HttpURLconnection",
        "getExternalStorageDirectory": "Read/Write External Storage",
        "getSimCountryIso": "getSimCountryIso",
        "execHttpRequest": "execHttpRequest",
        "Lorg/apache/http/client/methods/HttpPost": "HttpPost",
        "Landroid/telephony/SmsMessage;->getMessageBody": "readSMS",
        "sendTextMessage": "sendSMS",
        "getSubscriberId": "getSubscriberId",
        "getDeviceId": "getDeviceId",
        "getPackageInfo": "getPackageInfo",
        "getSystemService": "getSystemService",
        "getWifiState": "getWifiState",
        "system/bin/su": "system/bin/su",
        "setWifiEnabled": "setWifiEnabled",
        "setWifiDisabled": "setWifiDisabled",
        "getCellLocation": "getCellLocation",
        "getNetworkCountryIso": "getNetworkCountryIso",
        "SystemClock.uptimeMillis": "SystemClock.uptimeMillis",
        "getCellSignalStrength": "getCellSignalStrength",
        "Landroid/os/Build;->BRAND:Ljava/lang/String": "Access Device Info (BRAND)",
        "Landroid/os/Build;->DEVICE:Ljava/lang/String": "Access Device Info (DEVICE)",
        "Landroid/os/Build;->MODEL:Ljava/lang/String": "Access Device Info (MODEL)",
        "Landroid/os/Build;->PRODUCT:Ljava/lang/String": "Access Device Info (PRODUCT)",
        "Landroid/os/Build;->FINGERPRINT:Ljava/lang/String": "Access Device Info (FINGERPRINT)",
        "adb_enabled": "Check if adb is enabled",
        "Ljava/io/IOException;->printStackTrace": "printStackTrace",
        "Ljava/lang/Runtime;->exec": "Execution of external commands",
        "Ljava/lang/System;->loadLibrary": "Loading of external Libraries (loadLibrary)",
        "Ljava/lang/System;->load": "Loading of external Libraries (load)",
        "Ldalvik/system/DexClassLoader;": "Loading of external Libraries (DexClassLoader)",
        "Ldalvik/system/SecureClassLoader;": "Loading of external Libraries (SecureClassLoader)",
        "Ldalvik/system/PathClassLoader;": "Loading of external Libraries (PathClassLoader)",
        "Ldalvik/system/BaseDexClassLoader;": "Loading of external Libraries (BaseDexClassLoader)",
        "Ldalvik/system/URLClassLoader;": "Loading of external Libraries (URLClassLoader)",
        "android/os/Exec": "Execution of native code",
        "Base64": "Obfuscation(Base64)",
    }

    try:
        # Get list of all files in the directory
        file_list = [
            os.path.join(root, file)
            for root, _, files in os.walk(smali_location)
            for file in files
        ]

        logger.debug("-------------------------------------------")
        logger.debug("------------ Dangerous calls --------------")
        logger.debug("-------------------------------------------")
        for file_path in file_list:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()

                for idx, line in enumerate(lines):
                    line = line.strip()

                    for pattern, description in dangerous_patterns.items():
                        if pattern in line:
                            if pattern == "Cipher":
                                try:
                                    prev_line = lines[idx - 2].strip().split('"')[1]
                                    description = f"Cipher({prev_line})"
                                except IndexError:
                                    continue

                            if description and description not in dangerous_calls:
                                dangerous_calls.append(description)
                                logger.debug(f"Found: {description}")

            except Exception as e:
                logger.error(f"Error processing file {file_path}: {e}")
    except Exception as e:
        logger.error(f"Error traversing directory {smali_location}: {e}")

    logger.info("Finished smali call parsing")
    return dangerous_calls


def parse_smali_url(smali_location: str) -> list[str]:
    """
    Parse smali output files for URLs and IP addresses.

    Args:
        smali_location (str): Path to the directory containing smali files.

    Returns:
        list[str]: A list of unique URLs and IP addresses found in the smali files.
    """
    logger = get_logger()

    logger.info("Extracting URLs and IP addresses from smali files")

    extracted_data = []

    # Collect all files in the specified directory
    file_list = [
        os.path.join(root, filename)
        for root, _, files in os.walk(smali_location)
        for filename in files
    ]

    # Define regex patterns for URLs and IP addresses
    url_regex = re.compile(
        r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
    )
    ip_regex = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")

    logger.debug("-------------------------------------------")
    logger.debug("------------ URLs and IP addresses --------")
    logger.debug("-------------------------------------------")
    for file_path in file_list:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
                for line_number, line in enumerate(file, start=1):
                    line = line.strip()

                    # Search for URLs in the line
                    url_match = url_regex.search(line)
                    if url_match:
                        url = url_match.group()
                        if url not in extracted_data:
                            extracted_data.append(url)
                            logger.debug(f"URL: {url}")

                    # Search for IP addresses in the line
                    ip_match = ip_regex.search(line)
                    if ip_match:
                        ip = ip_match.group()
                        if ip not in extracted_data:
                            extracted_data.append(ip)
                            logger.debug(f"IP: {ip}")

        except Exception as e:
            logger.error(f"Error processing file {file_path}: {e}")

    logger.info("Finished extracting URLs and IP addresses")

    return extracted_data


def detect_ad_networks(smali_location: str, ad_libs_path: str) -> list[str]:
    """
    Detect Ad-Networks in the given smali files directory.

    Args:
        smali_location (str): Path to the directory containing smali files.
        ad_libs_path (str): Path to the CSV file containing Ad-Network paths.

    Returns:
        List[str]: A list of detected Ad-Networks.
    """
    logger = get_logger()
    logger.info("Detecting Ad-Networks in the smali files")

    # Read Ad-Network paths from the CSV file
    with open(ad_libs_path, "r", encoding="utf-8") as f:
        smali_paths = [(rec[0], rec[1]) for rec in csv.reader(f, delimiter=";")]

    # Collect all smali files in the given directory
    file_list = list(Path(smali_location).rglob("*.smali"))

    detected_ads = []

    logger.debug("----------------------------------------")
    logger.debug("--------- Detected Ad-Networks ---------")
    logger.debug("----------------------------------------")

    for ad_name, ad_path in smali_paths:
        ad_path_str = str(ad_path)
        for file_path in file_list:
            if ad_path_str in str(file_path):
                if ad_name not in detected_ads and ad_name:
                    detected_ads.append(ad_name)
                    logger.debug(f"Detected: {ad_name}")

    logger.info("Finished detecting Ad-Networks")
    return detected_ads
