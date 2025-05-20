from __future__ import annotations

import logging
import re
import shutil
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

import extension_settings  # External settings module
import psutil
import typer
from extension_logger import create_extension_logger  # External logger creation module
from rich.console import Console

import extractor  # External extraction module

# --- Constants ---
REPORT_FILENAME_PREFIX = "drebin-"
LOG_FILE_DIR_NAME = "logs"  # Directory name for individual APK logs
ANOMALY_FILENAME_SUFFIX = "_anomaly_apks.lst"  # Added

# Initialize Typer and Console
app = typer.Typer()
console = Console()


@dataclass
class APK:
    """
    Represents an individual APK file and its associated processing paths and status.
    """

    path: Path  # Path to the APK file
    base_working_dir: (
        Path  # Parent directory where this APK's working directory will be created
    )
    report_dir: Path  # Directory to save the generated report
    overwrite: bool = False  # Whether to overwrite existing reports

    name: str = field(init=False)  # APK filename (without extension)
    working_dir: Path = field(init=False)  # Dedicated working directory for this APK
    is_anomaly: bool = field(
        init=False, default=False
    )  # Flag indicating if errors or warnings were found during extraction

    def __post_init__(self):
        """
        Called automatically after instance initialization.
        Sets the APK name and its dedicated working directory.
        """
        self.name = self.path.stem
        self.working_dir = self.base_working_dir / self.name

    def check_log(self, logger_instance: logging.Logger) -> None:
        """
        Inspects the log file for this APK's extraction process for errors or warnings.
        """
        log_file = extension_settings.BASE_DIR / LOG_FILE_DIR_NAME / f"{self.name}.log"
        if not log_file.exists():
            logger_instance.warning(f"Log file not found for {self.name} at {log_file}")
            return

        error_pattern = re.compile(r" - ERROR - ")
        warning_pattern = re.compile(r" - WARNING - ")

        error_log_entries: list[str] = []
        warning_log_entries: list[str] = []

        try:
            with open(log_file, "r", encoding="utf-8") as f:
                for line in f:
                    if error_pattern.search(line):
                        error_log_entries.append(line.strip())
                    elif warning_pattern.search(line):
                        warning_log_entries.append(line.strip())
        except Exception as e:
            logger_instance.error(f"Error reading log file {log_file}: {e}")
            self.is_anomaly = True  # Consider log reading error as an anomaly
            return

        if error_log_entries:
            self.is_anomaly = True
            logger_instance.error(f"Errors found in log for {self.name}:")
            for error_entry in error_log_entries:
                logger_instance.error(f"  [ERROR_DETAIL {self.name}]: {error_entry}")

        if warning_log_entries:
            # Whether warnings constitute an anomaly depends on requirements
            self.is_anomaly = True
            logger_instance.warning(f"Warnings found in log for {self.name}:")
            for warning_entry in warning_log_entries:
                logger_instance.warning(
                    f"  [WARNING_DETAIL {self.name}]: {warning_entry}"
                )

    def delete_working_dir(self, logger_instance: logging.Logger) -> None:
        """
        Deletes the working directory for this APK.
        """
        if self.working_dir.exists():
            logger_instance.info(
                f"Deleting working directory for {self.name}: {self.working_dir}"
            )
            try:
                shutil.rmtree(self.working_dir)
            except OSError as e:
                logger_instance.error(
                    f"Failed to delete working directory for {self.name} ({self.working_dir}): {e}"
                )
        else:
            logger_instance.debug(
                f"Working directory for {self.name} does not exist (skipping deletion): {self.working_dir}"
            )

    def extract_feature(self, logger_instance: logging.Logger) -> None:
        """
        Extracts features from the APK file using the extractor module.
        """
        logger_instance.info(f"Starting feature extraction for {self.name}")
        report_file = self.report_dir / f"{REPORT_FILENAME_PREFIX}{self.name}.json"

        if report_file.exists() and not self.overwrite:
            logger_instance.info(
                f"Report already exists for {self.name} and overwrite is disabled. Skipping. ({report_file})"
            )
            return

        try:
            self.working_dir.mkdir(parents=True, exist_ok=True)

            extractor.run(
                self.path,
                self.report_dir,
                self.working_dir,
                console_logging=False,  # console_logging for extractor is fixed
            )
            logger_instance.info(f"Feature extraction completed for {self.name}")
        except Exception as e:
            logger_instance.error(
                f"Error during feature extraction for {self.name}: {e}"
            )
            self.is_anomaly = True  # Mark as anomaly if extraction fails
        finally:
            # Clean up working directory regardless of success or failure
            self.delete_working_dir(logger_instance)


@dataclass
class FeatureExtractor:
    """
    Manages the overall APK feature extraction process.
    """

    apk_dir: Path  # Directory containing APK files
    base_app_working_dir: Path  # Base working directory for the application (parent of individual APK working dirs)
    logger_instance: logging.Logger  # Logger instance
    report_dir: Path = Path("reports")  # Default directory for saving reports
    overwrite_reports: bool = False  # Default for overwriting existing reports
    apk_list: list[APK] = field(default_factory=list)
    anomaly_list_filepath: Path = field(init=False)  # Added

    def __post_init__(self):
        """
        Initializes paths that depend on other fields after the main __init__ has run.
        """
        self.anomaly_list_filepath = (
            self.report_dir / f"{self.apk_dir.name}{ANOMALY_FILENAME_SUFFIX}"
        )

    def make_apk_list(self, apk_list_file: Path | None = None) -> None:
        """
        Populates the list of APK objects from the APK directory or a specified list file.
        """
        apk_paths_to_process: list[Path] = []

        if apk_list_file and apk_list_file.exists():
            self.logger_instance.info(f"Using APK list file: {apk_list_file}")
            try:
                with open(apk_list_file, "r", encoding="utf-8") as f:
                    apk_filenames = [name.strip() for name in f if name.strip()]
                apk_paths_to_process = [self.apk_dir / name for name in apk_filenames]

                valid_apk_paths: list[Path] = []
                for p in apk_paths_to_process:
                    if p.exists() and p.is_file():
                        valid_apk_paths.append(p)
                    else:
                        self.logger_instance.warning(
                            f"APK file from list not found or is not a file: {p}"
                        )
                apk_paths_to_process = valid_apk_paths
            except Exception as e:
                self.logger_instance.error(
                    f"Error reading APK list file {apk_list_file}: {e}"
                )
                return  # Do not fall back to directory scan if list file processing fails
        else:
            if apk_list_file:  # File was specified but does not exist
                self.logger_instance.warning(
                    f"Specified APK list file not found: {apk_list_file}. Scanning directory {self.apk_dir} instead."
                )
            self.logger_instance.info(f"Scanning APK directory: {self.apk_dir}")
            apk_paths_to_process = list(self.apk_dir.glob("*.apk"))

        if not apk_paths_to_process:
            self.logger_instance.warning("No APK files found to process.")
            return

        self.apk_list = [
            APK(
                path=apk_path,
                base_working_dir=self.base_app_working_dir,
                report_dir=self.report_dir,
                overwrite=self.overwrite_reports,
            )
            for apk_path in apk_paths_to_process
        ]
        self.logger_instance.info(
            f"Listed {len(self.apk_list)} APK file(s) for processing."
        )

    def extract_all(self, max_workers: int = 4) -> None:
        """
        Performs feature extraction for all APKs in the list using a ProcessPoolExecutor.
        """
        if not self.apk_list:
            self.logger_instance.info(
                "No APKs in the list to extract features from. Skipping."
            )
            return

        self.logger_instance.info(
            f"Starting feature extraction for {len(self.apk_list)} APK(s) with {max_workers} worker(s)..."
        )

        # executor_instance変数をtryブロックの外で初期化し、
        # KeyboardInterruptハンドラ内でアクセスできるようにします。
        executor_instance: ProcessPoolExecutor | None = None
        try:
            with ProcessPoolExecutor(max_workers=max_workers) as executor:
                executor_instance = executor  # exceptブロックで参照できるように代入
                futures = {
                    executor.submit(apk.extract_feature, self.logger_instance): apk
                    for apk in self.apk_list
                }
                for future in futures:
                    apk_instance = futures[future]
                    try:
                        future.result()  # Wait for completion and retrieve result (or re-raise exception)
                    except Exception as e:
                        self.logger_instance.error(
                            f"An unexpected error occurred during parallel processing of APK {apk_instance.name}: {e}"
                        )
                        apk_instance.is_anomaly = True  # Ensure anomaly flag is set
        except KeyboardInterrupt:
            self.logger_instance.warning(
                "Feature extraction was interrupted by the user. Attempting to cancel tasks..."
            )
            if executor_instance is not None:
                self.logger_instance.info(
                    "Shutting down executor and attempting to cancel pending futures... (This may take a moment)"
                )
                # Python 3.9+ で利用可能な cancel_futures=True を使用してシャットダウンを試みます。
                # withステートメントの__exit__も executor.shutdown(wait=True) を呼び出しますが、
                # ここで明示的に呼び出すことで、より積極的にキャンセルを試みます。
                executor_instance.shutdown(wait=True, cancel_futures=True)
            raise  # KeyboardInterruptを再送出して、スクリプト全体を停止させます。
        except Exception as e:
            self.logger_instance.critical(
                f"A critical error occurred during parallel feature extraction: {e}"
            )
            # executor_instanceが初期化され、ここでKeyboardInterrupt以外のエラーが発生した場合、
            # 'with'ステートメントの__exit__がシャットダウンを処理します。

        self.logger_instance.info(
            "Feature extraction process for all APKs has completed."
        )

    def check_anomalies(self) -> None:
        """
        Checks the logs for all processed APKs and writes a list of anomalous APKs to a file.
        """
        self.logger_instance.info("Checking for anomalies in log files...")
        if not self.apk_list:
            self.logger_instance.info("No APKs were processed, skipping anomaly check.")
            return

        for apk in self.apk_list:
            apk.check_log(self.logger_instance)

        anomaly_apks = [apk for apk in self.apk_list if apk.is_anomaly]
        anomaly_count = len(anomaly_apks)

        if anomaly_count > 0:
            self.logger_instance.warning(
                f"{anomaly_count} APK(s) found with anomalies during extraction."
            )
            self.logger_instance.warning(
                f"Check the '{self.anomaly_list_filepath}' file for details."
            )
            try:
                # Ensure the directory for the anomaly list file exists
                self.anomaly_list_filepath.parent.mkdir(parents=True, exist_ok=True)
                with open(self.anomaly_list_filepath, "a", encoding="utf-8") as f:
                    for apk in anomaly_apks:
                        f.write(f"{apk.path.name}\n")  # Record original APK filename
            except IOError as e:
                self.logger_instance.error(
                    f"Error writing to anomaly list file {self.anomaly_list_filepath}: {e}"
                )
        else:
            self.logger_instance.info("No anomalies found during extraction.")
        self.logger_instance.info("Anomaly check completed.")


@app.command()
def main(
    apk_dir: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
        help="Directory containing APK files.",
    ),
    apk_list_file_path: Path = typer.Option(
        None,
        "--apk-list",  # Added a more conventional option name
        help="Path to a file containing a list of APK filenames to process. If not specified, all APKs in apk_dir are processed.",
        resolve_path=True,
    ),
    report_dir: Path = typer.Option(
        "reports",
        "--report-dir",
        help="Directory to save the generated JSON reports.",
        resolve_path=True,
    ),
    overwrite: bool = typer.Option(
        False, "--overwrite", help="Overwrite existing reports if they exist."
    ),
    log_file_path: Path = typer.Option(
        "feature_extraction.log",
        "--log-file",
        help="Path to the main log file.",
        resolve_path=True,
    ),
    console_logging: bool = typer.Option(
        True,
        "--console-log/--no-console-log",  # Typer's way for boolean switches
        help="Enable or disable console logging.",
    ),
):
    """
    Extracts features from APK files and generates JSON reports.
    """
    logger: logging.Logger = create_extension_logger(
        log_file_path=log_file_path,
        logger_name="apk_feature_extractor",  # Changed logger name slightly
        console_logging_enabled=console_logging,
    )
    logger.info("APK Feature Extractor process started.")
    logger.info(
        f"Arguments: apk_dir='{apk_dir}', apk_list_file_path='{apk_list_file_path}', report_dir='{report_dir}', overwrite={overwrite}, log_file='{log_file_path}', console_logging={console_logging}"
    )

    try:
        report_dir.mkdir(parents=True, exist_ok=True)
        apk_specific_log_dir = extension_settings.BASE_DIR / LOG_FILE_DIR_NAME
        apk_specific_log_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Report directory: {report_dir}")
        logger.info(f"Individual APK log directory: {apk_specific_log_dir}")
    except OSError as e:
        logger.error(f"Failed to create necessary directories: {e}")
        raise typer.Exit(code=1)

    base_app_working_dir = extension_settings.WORKING_DIR
    try:
        base_app_working_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Base application working directory: {base_app_working_dir}")
    except OSError as e:
        logger.error(
            f"Failed to create base application working directory {base_app_working_dir}: {e}"
        )
        raise typer.Exit(code=1)

    feature_extractor = FeatureExtractor(
        apk_dir=apk_dir,
        base_app_working_dir=base_app_working_dir,
        logger_instance=logger,
        report_dir=report_dir,
        overwrite_reports=overwrite,
    )

    try:
        feature_extractor.make_apk_list(apk_list_file=apk_list_file_path)

        physical_cores = psutil.cpu_count(logical=False)
        max_workers_to_use = (
            physical_cores if physical_cores and physical_cores > 0 else 4
        )
        logger.info(
            f"Using a maximum of {max_workers_to_use} worker(s). (Physical cores: {physical_cores})"
        )

        feature_extractor.extract_all(max_workers=max_workers_to_use)
        feature_extractor.check_anomalies()

    except Exception as e:
        logger.critical(
            f"An unexpected error occurred during the main process: {e}", exc_info=True
        )
        raise typer.Exit(code=1)
    finally:
        if base_app_working_dir.exists():
            logger.info(
                f"Cleaning up base application working directory: {base_app_working_dir}"
            )
            try:
                shutil.rmtree(base_app_working_dir)
                logger.info("Base application working directory successfully deleted.")
            except OSError as e:
                logger.error(
                    f"Failed to delete base application working directory {base_app_working_dir}: {e}"
                )
        logger.info("APK Feature Extractor process finished.")


if __name__ == "__main__":
    app()
