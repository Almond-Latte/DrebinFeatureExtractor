#########################################################################################
#                                     Disclaimer                                        #
#########################################################################################
# (c) 2014, Mobile-Sandbox
# Michael Spreitzenbarth (research@spreitzenbarth.de)
#
# This program is free software you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#########################################################################################

import shutil
from pathlib import Path

import typer

import settings
from analyzer.apk_info import (
    get_activities,
    get_files_inside_apk,
    get_providers,
    get_sample_info,
    get_services_receivers,
)
from analyzer.features import get_features
from analyzer.intents import get_intents
from analyzer.network import get_net
from analyzer.permissions import check_api_permissions, get_permissions
from analyzer.smali import detect_ad_networks, dex2x, parse_smali_calls, parse_smali_url
from logger import create_logger
from report.generator import create_report
from unpacker import unpack_sample

app = typer.Typer()


def run(
    sample_file: Path, report_dir: Path, working_dir: Path, console_logging: bool = True
):
    """
    Main program to analyze the APK sample and generate a report.

    Args:
        sample_file (str): Path to the APK sample file.
        report_dir (str): Path to the report directory.
        working_dir (str): Path to the working directory.
    """

    apk_name = Path(sample_file).stem
    log_dir = settings.LOG_DIR

    # Initialize logger
    logger = create_logger(log_dir, apk_name, console_logging)
    logger.info("Starting analysis...")

    working_dir = Path(working_dir).resolve()
    working_dir.mkdir(parents=True, exist_ok=True)

    # Unpack sample
    unpack_location = unpack_sample(working_dir, sample_file)

    # Extract data from the APK
    app_net = get_net(sample_file)
    app_infos = get_sample_info(sample_file)
    app_providers = get_providers(sample_file)
    app_permissions = get_permissions(sample_file)
    app_activities = get_activities(sample_file)
    app_features = get_features(sample_file)
    app_intents = get_intents(sample_file)
    app_files = get_files_inside_apk(sample_file)
    services_and_receiver = get_services_receivers(sample_file)
    ssdeep_value = hash(sample_file)

    # Initialize result containers
    dangerous_calls = []
    app_urls = []
    api_permissions = []
    api_calls = []
    detected_ads = []

    # Process dex files
    dex_files = list(Path(unpack_location).glob("*.dex"))
    for dex in dex_files:
        # Decompile dex to smali
        logger.info(f"Processing {dex}")
        smali_location = dex2x(working_dir, dex)

        # Analyze smali code
        dangerous_calls.extend(parse_smali_calls(smali_location))
        app_urls.extend(parse_smali_url(smali_location))

        perms, calls = check_api_permissions(smali_location)
        api_permissions.extend(perms)
        api_calls.extend(calls)

        detected_ads.extend(detect_ad_networks(smali_location, settings.ADSLIBS))

        # Clean up smali directory
        shutil.rmtree(smali_location)

    # Clean up working directory
    shutil.rmtree(working_dir)

    create_report(
        report_dir,
        app_net,
        app_providers,
        app_permissions,
        app_features,
        app_intents,
        services_and_receiver,
        detected_ads,
        dangerous_calls,
        app_urls,
        app_infos,
        api_permissions,
        api_calls,
        app_files,
        app_activities,
        ssdeep_value,
    )


@app.command()
def main(
    sample_file: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=False,
        help="Path to the APK file.",
    ),
    report_dir: Path = typer.Argument(
        ...,
        exists=False,
        file_okay=False,
        dir_okay=True,
        help="Path to the report directory.",
    ),
    working_dir: Path = typer.Argument(..., help="Path to the working directory."),
    console_logging: bool = typer.Option(
        settings.CONSOLE_LOGGING, help="Enable or disable console logging."
    ),
):
    """
    Analyze an APK file and save the results in the working directory.

    Args:
        sample_file (Path): Path to the APK file.
        working_dir (Path): Path to the working directory.
        console_logging (bool): Enable or disable console logging.
    """
    # Resolve the working directory and create it if necessary
    working_dir = working_dir.resolve()
    working_dir.mkdir(parents=True, exist_ok=True)

    # Resolve the APK file path
    apk_file = sample_file.resolve()

    # Call the run function
    typer.echo(f"Extracting {apk_file} in {working_dir}...")
    run(apk_file, report_dir, working_dir, console_logging)
    typer.echo("Extraction completed.")


if __name__ == "__main__":
    app()
