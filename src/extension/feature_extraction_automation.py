import re
import shutil
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

import extension_settings
import psutil
import typer
from extension_logger import create_extension_logger
from rich.console import Console

import extractor

# Initialize Typer and Console
app = typer.Typer()
console = Console()

# Global logger instance
logger = None


@dataclass
class APK:
    """
    Represents an APK file and its associated processing paths.
    """

    path: Path
    name: str = field(init=False)
    report_dir: Path = None
    overwrite: bool = False
    working_dir: Path = None

    def __post_init__(self):
        self.name = self.path.stem  # Automatically extract the name from the path
        self.is_anomaly = (
            False  # Flag to indicate if error or warning were found during extraction
        )

    def set_working_dir(self, working_dir: Path) -> None:
        self.working_dir = working_dir

    def check_log(self) -> None:
        """
        Check the error log file for any issues during extraction.
        """
        log_file = extension_settings.BASE_DIR / "logs" / f"{self.name}.log"
        if not log_file.exists():
            logger.warning(f"No log found for {self.name}")
            return

        error_pattern = re.compile(r" - ERROR - ")
        warning_pattern = re.compile(r" - WARNING - ")

        error_log = []
        warning_log = []

        with open(log_file, "r") as f:
            for line in f:
                if error_pattern.search(line):
                    error_log.append(line)
                if warning_pattern.search(line):
                    warning_log.append(line)

        if error_log:
            self.is_anomaly = True
            logger.error(f"Errors found in log for {self.name}")
            for error in error_log:
                logger.error(
                    f"{error} in {self.name}. Check the log file for more details."
                )

        if warning_log:
            self.is_anomaly = True
            logger.warning(f"Warnings found in log for {self.name}")
            for warning in warning_log:
                logger.warning(
                    f"{warning} in {self.name}. Check the log file for more details."
                )

    def delete_working_dir(self) -> None:
        """
        Delete the working directory after extraction.
        """
        if self.working_dir.exists():
            logger.info(f"Deleting working directory for {self.name}")
            shutil.rmtree(self.working_dir)

    def extract_feature(self) -> None:
        """
        Extract features from the APK file using the extractor module.
        """

        logger.info(f"Extracting features for {self.name}...")
        report_file = self.report_dir / f"drebin-{self.name}.json"
        if report_file.exists() and not self.overwrite:
            logger.info(f"Report already exists for {self.name}")
            return
        extractor.run(
            self.path, self.report_dir, self.working_dir, console_logging=False
        )
        logger.info(f"Feature extraction completed for {self.name}")
        self.delete_working_dir()


@dataclass
class FeatureExtractor:
    """
    Manages APK feature extraction and report generation.
    """

    apk_dir: Path
    working_dir: Path
    log_file: Path = "feature_extraction.log"
    report_dir: Path = Path("reports")
    overwrite: bool = False
    console_logging: bool = True
    apk_list: list[APK] = field(default_factory=list)

    def make_apk_list(self, apk_list_file: Path = None) -> None:
        """
        Populate the list of APK objects from the APK directory.
        """
        if apk_list_file and apk_list_file.exists():
            with open(apk_list_file, "r") as f:
                apk_names = f.readlines()
            apk_paths = [self.apk_dir / name.strip() for name in apk_names]
            self.apk_list = [
                APK(Path(path), self.report_dir, self.overwrite) for path in apk_paths
            ]
            logger.info(f"Found {len(self.apk_list)} APK files in {apk_list_file}")
        else:
            self.apk_list = [
                APK(path, self.report_dir) for path in self.apk_dir.glob("*.apk")
            ]
            logger.info(f"Found {len(self.apk_list)} APK files in {self.apk_dir}")

        for apk in self.apk_list:
            unpack_dir = self.working_dir / apk.name
            apk.set_working_dir(unpack_dir)

    def extract_all(self, max_workers: int = 4) -> None:
        """
        Perform feature extraction for all APKs using a process pool.

        Args:
            max_workers (int): Number of worker processes for parallel execution.

        """
        logger.info(f"Starting feature extraction with {max_workers} workers...")
        try:
            with ProcessPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(apk.extract_feature): apk for apk in self.apk_list
                }
                for future, apk in fetures.items():
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"Error during extraction: {e} in {apk.name}")

        except KeyboardInterrupt:
            logger.warning("Feature extraction interrupted by user.")
            executor.shutdown(wait=False, cancel_futures=True)
            raise  # Re-raise the KeyboardInterrupt to exit the program

        logger.info("Feature extraction completed.")

    def check_anomalies(self) -> None:
        """
        Check the log files for any anomalies during extraction.
        """

        logger.info("Checking for anomalies in the log files...")

        for apk in self.apk_list:
            apk.check_log()

        anomaly_count = sum(apk.is_anomaly for apk in self.apk_list)
        if anomaly_count:
            logger.warning(f"{anomaly_count} anomaly apks found during extraction.")
            logger.warning("Check the 'anomaly_apks.lst' file")
            with open("anomaly_apks.lst", "w") as f:
                for apk in self.apk_list:
                    if apk.is_anomaly:
                        f.write(f"{apk.name}.apk\n")
        else:
            logger.info("No anomaly apks found during extraction.")
        logger.info("Anomaly check completed.")


@app.command()
def main(
    apk_dir: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=False,
        dir_okay=True,
        help="Directory containing APK files.",
    ),
    apk_list: Path = typer.Option(
        "apk_list.lst", help="Path to the list of APK files."
    ),
    report_dir: Path = typer.Option(
        "reports", help="Directory to save the JSON reports."
    ),
    overwrite: bool = typer.Option(
        False, help="Overwrite existing reports if they exist."
    ),
    log_file: Path = typer.Option(
        "feature_extraction.log", help="Path to the log file for logging."
    ),
    console_logging: bool = typer.Option(
        True, help="Enable or disable console logging."
    ),
):
    """
    Main command to execute APK feature extraction.

    Args:
        apk_dir (Path): Directory containing APK files.
        report_dir (Path): Directory to save reports.
        log_file (Path, optional): Log file path for extension-specific logs.
    """
    # Initialize logger
    global logger
    logger = create_extension_logger(log_file, "feature_extraction", console_logging)

    # Initialize FeatureExtractor
    working_dir = extension_settings.WORKING_DIR
    feature_extractor = FeatureExtractor(
        apk_dir, working_dir, log_file, report_dir, overwrite, console_logging
    )

    # Execute extraction process
    feature_extractor.make_apk_list(apk_list_file=apk_list)
    max_workers = psutil.cpu_count(logical=False)
    feature_extractor.extract_all(max_workers=max_workers)
    feature_extractor.check_anomalies()
    shutil.rmtree(working_dir)


if __name__ == "__main__":
    app()
