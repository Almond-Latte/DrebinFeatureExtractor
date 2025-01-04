import json
from pathlib import Path

from logger import get_logger


def create_output(
    working_dir: str,
    app_net: list[str],
    app_providers: list[str],
    app_permissions: list[str],
    app_features: list[str],
    app_intents: list[str],
    services_and_receiver: list[str],
    detected_ads: list[str],
    dangerous_calls: list[str],
    app_urls: list[str],
    app_infos: list[str],
    api_permissions: list[str],
    api_calls: list[list[str]],
    app_files: list[str],
    app_activities: list[str],
    ssdeep_value: str,
) -> dict[str, int]:
    """
    Create a JSON output file from the given app data.

    Args:
        working_dir (str): Directory to save the JSON output.
        app_net (list[str]): Network information.
        app_providers (list[str]): App providers.
        app_permissions (list[str]): Permissions used by the app.
        app_features (list[str]): Features used by the app.
        app_intents (list[str]): Intents used by the app.
        services_and_receiver (list[str]): Services and receivers.
        detected_ads (list[str]): Detected ad networks.
        dangerous_calls (list[str]): Interesting or dangerous calls.
        app_urls (list[str]): URLs found in the app.
        app_infos (list[str]): Basic app information [sha256, md5, package, sdk version, apk name].
        api_permissions (list[str]): Permissions derived from APIs.
        api_calls (list[list[str]]): API calls made by the app.
        app_files (list[str]): Files included in the app.
        app_activities (list[str]): Activities in the app.
        ssdeep_value (str): SSDEEP hash of the app.

    Returns:
        dict[str, int]: A dictionary with the processed feature vector.
    """
    logger = get_logger()
    logger.info("Creating JSON output...")

    output = {
        "sha256": app_infos[0],
        "md5": app_infos[1],
        "ssdeep": ssdeep_value,
        "package_name": app_infos[2],
        "sdk_version": app_infos[3],
        "apk_name": app_infos[4],
        "app_permissions": app_permissions,
        "api_permissions": api_permissions,
        "api_calls": api_calls,
        "features": app_features,
        "intents": app_intents,
        "activities": app_activities,
        "s_and_r": services_and_receiver,
        "interesting_calls": dangerous_calls,
        "urls": app_urls,
        "networks": app_net,
        "providers": app_providers,
        "included_files": app_files,
        "detected_ad_networks": detected_ads,
    }

    # Ensure output directories exist
    working_path = Path(working_dir)
    results_path = working_path / "results"
    results_path.mkdir(parents=True, exist_ok=True)

    run_id = f"drebin-{app_infos[0]}"

    processed_output = report_to_feature_vector(output)
    output_path = results_path / f"{run_id}.json"

    logger.info(f"Saving JSON output to {output_path}")

    with output_path.open("w", encoding="utf-8") as json_file:
        json.dump(processed_output, json_file, indent=4)

    return processed_output


def report_to_feature_vector(report: dict[str, any]) -> dict[str, int]:
    """
    Convert the report dictionary into a feature vector format.

    Args:
        report (dict[str, any]): Original report dictionary.

    Returns:
        dict[str, int]: Processed feature vector dictionary.
    """
    output = {"sha256": report["sha256"]}

    def key_fmt(k: str, val: str) -> str:
        return f"{k}::{val.strip()}".replace(".", "_")

    for k, values in report.items():
        if k in {
            "intents",
            "features",
            "urls",
            "api_calls",
            "interesting_calls",
            "app_permissions",
            "api_permissions",
            "activities",
            "s_and_r",
            "providers",
        }:
            if k == "api_calls":
                for val in values:
                    if val[0].strip():
                        line = key_fmt(k, val[0])
                        output[line] = 1

            elif k == "interesting_calls":
                for val in values:
                    if "HttpPost" in val:
                        line = key_fmt(k, val.split(" ")[0])
                        output[line] = 1
                    elif "(" in val and ";" in val:
                        continue
                    elif val.strip():
                        line = key_fmt(k, val)
                        output[line] = 1

            else:
                for val in values:
                    if val.strip():
                        line = key_fmt(k, val)
                        output[line] = 1

    return output
