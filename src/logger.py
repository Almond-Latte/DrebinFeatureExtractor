import json
import logging
from logging.config import dictConfig
from pathlib import Path

# Global logger instance
logger = None


def create_logger(
    log_dir: Path,
    apk_name: str,
    console_logging: bool = True,
    log_level: int = logging.DEBUG,
) -> logging.Logger:
    """
    Configure and return a logger instance.

    Args:
        log_dir (Path): Path to the directory where log files will be stored.
        apk_name (str): Name of the APK being analyzed, used for log file naming.
        console_logging (bool): Enable or disable console logging. Default is True.
        log_level (int): Log level for the logger. Default is logging.DEBUG.

    Returns:
        logging.Logger: Configured logger instance.
    """
    global logger
    # Ensure log directory exists
    log_dir.mkdir(parents=True, exist_ok=True)

    # Define log file path with sanitized app name
    sanitized_app_name = apk_name.replace(" ", "_").replace("/", "_")
    log_file = log_dir / f"{sanitized_app_name}.log"

    # Default logger configuration
    default_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "standard": {
                "format": "%(asctime)s - %(name)s - %(levelname)s - [%(module)s:%(funcName)s] - %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S",
            },
            "console": {
                "level": log_level,
                "format": "%(message)s",
            },
        },
        "handlers": {
            "fileHandler": {
                "level": "DEBUG",
                "class": "logging.FileHandler",
                "formatter": "standard",
                "filename": str(log_file),
                "encoding": "utf8",
            },
        },
        "root": {
            "level": "DEBUG",
            "handlers": ["fileHandler"],
        },
    }

    # Add RichHandler for console logging if enabled
    if console_logging:
        default_config["handlers"]["rich"] = {
            "level": log_level,
            "class": "rich.logging.RichHandler",
            "formatter": "console",
            "rich_tracebacks": True,  # Enable rich tracebacks for better error visibility
        }
        default_config["root"]["handlers"].append("rich")

    # Try loading a logger configuration from `logger_config.json`
    config_file = Path(__file__).parent / "logger_config.json"
    if config_file.exists():
        try:
            with config_file.open("r", encoding="utf-8") as f:
                config = json.load(f)
                config["handlers"]["fileHandler"]["filename"] = str(log_file)
        except Exception as e:
            print(f"Failed to load logger configuration from {config_file}: {e}")
            config = default_config
    else:
        config = default_config

    # Configure the logger
    dictConfig(config)
    logger = logging.getLogger("DrebinFeatureExtractor")
    logger.info(f"Logger initialized. Logs will be written to {log_file}")
    if not console_logging:
        logger.info("Console logging is disabled.")
    return logger


def get_logger() -> logging.Logger:
    """
    Get the logger instance.

    Returns:
        logging.Logger: Logger instance.
    """
    if logger is None:
        raise RuntimeError("Logger is not initialized. Call `create_logger()` first.")

    return logger
