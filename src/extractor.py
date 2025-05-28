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

import logging
import shutil
from pathlib import Path

import ssdeep
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
    The working_dir is expected to be created and cleaned up by the caller.
    This function will clean up temporary subdirectories it creates within working_dir.
    """

    apk_name = sample_file.stem
    log_dir = Path(settings.LOG_DIR)

    # Initialize logger
    logger: logging.Logger = create_logger(log_dir, apk_name, console_logging)
    logger.info(f"Starting analysis for {apk_name} in working directory: {working_dir}")

    # Initialize result containers with default values
    app_net = {}
    app_infos = {}
    app_providers: list[str] = []
    app_permissions: list[str] = []
    app_activities: list[str] = []
    app_features: list[str] = []
    app_intents: list[str] = []
    app_files: list[str] = []
    services_and_receiver: list[str] = []
    ssdeep_value: str = "N/A"

    dangerous_calls: list[str] = []
    app_urls: list[str] = []
    api_permissions_list: list[str] = []
    api_calls: list[str] = []
    detected_ads: list[str] = []

    unpack_location: Path | None = None

    try:
        # Unpack sample
        try:
            logger.info(f"Unpacking {sample_file} into {working_dir}")
            unpack_location = unpack_sample(working_dir, sample_file)
            if not unpack_location or not Path(unpack_location).is_dir():
                logger.error(
                    f"Failed to unpack sample or unpack location '{unpack_location}' is not a valid directory."
                )
                unpack_location = None
            else:
                logger.info(f"Sample unpacked to {unpack_location}")
        except KeyboardInterrupt:
            logger.warning("Unpacking interrupted by user.")
            raise
        except Exception as e:
            logger.error(f"Error during unpacking: {e}", exc_info=settings.DEBUG)
            unpack_location = None

        # Extract data from the APK - wrap each call in try-except
        try:
            app_net = get_net(sample_file)
        except Exception as e:
            logger.warning(f"Could not get network info: {e}", exc_info=settings.DEBUG)
        try:
            app_infos = get_sample_info(sample_file)
        except Exception as e:
            logger.warning(f"Could not get sample info: {e}", exc_info=settings.DEBUG)
        try:
            app_providers = get_providers(sample_file)
        except Exception as e:
            logger.warning(f"Could not get providers: {e}", exc_info=settings.DEBUG)
        try:
            app_permissions = get_permissions(sample_file)
        except Exception as e:
            logger.warning(f"Could not get permissions: {e}", exc_info=settings.DEBUG)
        try:
            app_activities = get_activities(sample_file)
        except Exception as e:
            logger.warning(f"Could not get activities: {e}", exc_info=settings.DEBUG)
        try:
            app_features = get_features(sample_file)
        except Exception as e:
            logger.warning(f"Could not get features: {e}", exc_info=settings.DEBUG)
        try:
            app_intents = get_intents(sample_file)
        except Exception as e:
            logger.warning(f"Could not get intents: {e}", exc_info=settings.DEBUG)
        try:
            app_files = get_files_inside_apk(sample_file)
        except Exception as e:
            logger.warning(
                f"Could not get files inside apk: {e}", exc_info=settings.DEBUG
            )
        try:
            services_and_receiver = get_services_receivers(sample_file)
        except Exception as e:
            logger.warning(
                f"Could not get services/receivers: {e}", exc_info=settings.DEBUG
            )

        # Calculate ssdeep hash using 'ssdeep' library
        try:
            if sample_file.is_file():
                ssdeep_value = ssdeep.hash_from_file(str(sample_file))
                if not ssdeep_value:
                    ssdeep_value = "N/A (ssdeep hashing failed)"
                    logger.warning(
                        f"ssdeep.hash_from_file failed for {sample_file.name}."
                    )
                else:
                    logger.info(
                        f"ssdeep hash for {sample_file.name}: {ssdeep_value}"
                    )
            else:
                logger.warning(
                    f"Sample file {sample_file} not found for ssdeep hashing."
                )
                ssdeep_value = "N/A (file not found)"
        except Exception as e:
            logger.warning(
                f"Could not generate ssdeep hash for {sample_file.name} using 'ssdeep' library: {e}",
                exc_info=settings.DEBUG,
            )
            ssdeep_value = f"N/A (ssdeep error: {type(e).__name__})"

        if unpack_location:
            dex_files = list(Path(unpack_location).glob("*.dex"))
            if not dex_files:
                logger.info(f"No .dex files found in {unpack_location}.")
            else:
                logger.info(f"Found {len(dex_files)} .dex file(s) for processing.")

            for dex_file_path in dex_files:
                smali_location: Path | None = None
                try:
                    logger.info(f"Processing {dex_file_path.name}...")
                    smali_location = dex2x(working_dir, dex_file_path)

                    if not smali_location or not smali_location.is_dir():
                        logger.warning(
                            f"Smali conversion failed or produced no output directory for {dex_file_path.name} at {smali_location}."
                        )
                        continue

                    logger.info(f"Analyzing smali code at {smali_location}")
                    dangerous_calls.extend(parse_smali_calls(smali_location))
                    app_urls.extend(parse_smali_url(smali_location))

                    perms, calls = check_api_permissions(smali_location)
                    api_permissions_list.extend(perms)
                    api_calls.extend(calls)

                    detected_ads.extend(
                        detect_ad_networks(smali_location, settings.ADSLIBS)
                    )
                except KeyboardInterrupt:
                    logger.warning(
                        f"Keyboard interrupt during smali processing of {dex_file_path.name}."
                    )
                    raise
                except Exception as e:
                    logger.error(
                        f"Error processing smali for {dex_file_path.name}: {e}",
                        exc_info=settings.DEBUG,
                    )
                finally:
                    if (
                        smali_location
                        and smali_location.is_dir()
                        and smali_location.exists()
                    ):
                        logger.info(f"Cleaning up smali directory: {smali_location}")
                        shutil.rmtree(smali_location, ignore_errors=True)
        else:
            logger.warning(
                "Unpack location is not valid or unpacking failed. Skipping dex processing."
            )

        logger.info("Creating report...")
        create_report(
            report_dir=report_dir,
            app_net=app_net,
            app_providers=app_providers,
            app_permissions=app_permissions,
            app_features=app_features,
            app_intents=app_intents,
            services_and_receiver=services_and_receiver,
            detected_ads=detected_ads,
            dangerous_calls=dangerous_calls,
            app_urls=app_urls,
            app_infos=app_infos,
            api_permissions=api_permissions_list,
            api_calls=api_calls,
            app_files=app_files,
            app_activities=app_activities,
            ssdeep_value=ssdeep_value,
        )
        logger.info(f"Analysis for {apk_name} finished successfully.")

    except KeyboardInterrupt:
        logger.warning(
            f"Analysis for {apk_name} interrupted by user. Partial results may be missing."
        )
        raise
    except Exception as e:
        logger.critical(
            f"A critical error occurred during the analysis of {apk_name}: {e}",
            exc_info=True,
        )
    finally:
        logger.info(f"Finalizing analysis process for {apk_name}.")


@app.command()
def main(
    sample_file: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=False,
        resolve_path=True,
        help="Path to the APK file.",
    ),
    report_dir: Path = typer.Argument(
        ...,
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
        help="Path to the report directory.",
    ),
    working_dir: Path = typer.Argument(
        ...,
        resolve_path=True,
        help="Path to the working directory (will be created if it doesn't exist).",
    ),
    console_logging: bool = typer.Option(
        settings.CONSOLE_LOGGING, help="Enable or disable console logging."
    ),
):
    """
    Analyze an APK file and save the results.
    The working directory is created by this command and cleaned up afterwards.
    """
    resolved_working_dir = working_dir.resolve()
    resolved_report_dir = report_dir.resolve()
    apk_file = sample_file.resolve()

    logger = create_logger(
        Path(settings.LOG_DIR), apk_file.stem + "_main", console_logging
    )
    logger.info(f"CLI main invoked for {apk_file.name}")

    try:
        logger.info(f"Creating working directory: {resolved_working_dir}")
        resolved_working_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Ensuring report directory exists: {resolved_report_dir}")
        resolved_report_dir.mkdir(parents=True, exist_ok=True)

        typer.echo(
            f"Extracting {apk_file} using working directory {resolved_working_dir} and report directory {resolved_report_dir}..."
        )
        run(apk_file, resolved_report_dir, resolved_working_dir, console_logging)
        typer.echo("Extraction completed.")

    except KeyboardInterrupt:
        logger.warning("Main process interrupted by user.")
        typer.echo("Extraction process interrupted.")
    except Exception as e:
        logger.critical(f"Error in main execution: {e}", exc_info=True)
        typer.echo(f"An error occurred: {e}", err=True)
    finally:
        if resolved_working_dir.exists():
            logger.info(f"Cleaning up working directory: {resolved_working_dir}")
            try:
                shutil.rmtree(resolved_working_dir)
                logger.info("Working directory cleaned up successfully.")
            except Exception as e:
                logger.error(
                    f"Failed to clean up working directory {resolved_working_dir}: {e}",
                    exc_info=True,
                )
        logger.info(f"CLI main for {apk_file.name} finished.")


if __name__ == "__main__":
    app()
