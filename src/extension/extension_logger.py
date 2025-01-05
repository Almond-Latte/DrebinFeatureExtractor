import json
import logging
from logging.config import dictConfig
from pathlib import Path


def create_extension_logger(
    log_file: Path,
    log_name: str = "extension",
    console_logging: bool = True,
    log_level: int = logging.DEBUG,
) -> logging.Logger:
    """
    Configure and return an extension-specific logger instance with Rich support.

    Args:
        log_dir (Path): Path to the directory where log files will be stored.
        log_name (str): Name of the logger. Default is 'extension'.
        console_logging (bool): Enable or disable console logging. Default is True.
        log_level (int): Log level for the logger. Default is logging.DEBUG.

    Returns:
        logging.Logger: Configured logger instance.
    """
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
        "loggers": {
            log_name: {
                "level": log_level,
                "handlers": ["fileHandler"],
                "propagate": False,
            },
        },
    }

    # Add RichHandler for console logging if enabled
    if console_logging:
        default_config["handlers"]["rich"] = {
            "level": log_level,
            "class": "rich.logging.RichHandler",
            "rich_tracebacks": True,
        }
        default_config["loggers"][log_name]["handlers"].append("rich")

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
    logger = logging.getLogger(log_name)
    logger.info(f"Logger '{log_name}' initialized. Logs will be written to {log_file}")
    if not console_logging:
        logger.info("Console logging is disabled.")
    return logger
