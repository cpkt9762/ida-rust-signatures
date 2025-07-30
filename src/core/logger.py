"""Logging configuration and utilities for Rust x86_64 IDA signatures generator.

This module provides centralized logging setup with proper formatting,
level configuration, and file output capabilities.
"""

import logging
import sys
from pathlib import Path
from typing import Optional

from colorama import Fore, Style, init as colorama_init

# Initialize colorama for cross-platform colored output
colorama_init(autoreset=True)


class ColoredFormatter(logging.Formatter):
    """Custom formatter with color support for different log levels."""
    
    # Color mapping for log levels
    COLORS = {
        logging.DEBUG: Fore.CYAN,
        logging.INFO: Fore.GREEN,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.MAGENTA + Style.BRIGHT,
    }
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record with appropriate colors."""
        # Get the original formatted message
        formatted = super().format(record)
        
        # Apply color based on log level
        color = self.COLORS.get(record.levelno, "")
        if color and sys.stderr.isatty():  # Only colorize if output is a terminal
            formatted = f"{color}{formatted}{Style.RESET_ALL}"
        
        return formatted


def setup_logging(
    level: str = "INFO",
    log_file: Optional[Path] = None,
    verbose: bool = False
) -> None:
    """Set up logging configuration for the application.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_file: Optional path to log file for persistent logging.
        verbose: Enable verbose console output.
    """
    # Convert string level to logging constant
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    
    # Create root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)  # Set to DEBUG to capture all messages
    
    # Clear any existing handlers
    root_logger.handlers.clear()
    
    # Console handler with colors
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(numeric_level if not verbose else logging.DEBUG)
    
    console_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    if verbose:
        console_format = "%(asctime)s - %(name)s:%(lineno)d - %(levelname)s - %(message)s"
    
    console_formatter = ColoredFormatter(console_format)
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)
    
    # File handler (if specified)
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)  # Log everything to file
        
        file_format = "%(asctime)s - %(name)s:%(lineno)d - %(levelname)s - %(message)s"
        file_formatter = logging.Formatter(file_format)
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)
    
    # Set specific logger levels to reduce noise
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    

def get_logger(name: str) -> logging.Logger:
    """Get a logger instance for the specified module.
    
    Args:
        name: Logger name, typically __name__ from the calling module.
        
    Returns:
        Configured logger instance.
    """
    return logging.getLogger(name)


class LoggerMixin:
    """Mixin class to provide logging capabilities to other classes."""
    
    @property
    def logger(self) -> logging.Logger:
        """Get logger instance for this class."""
        return get_logger(f"{self.__class__.__module__}.{self.__class__.__name__}")


def log_execution_time(func):
    """Decorator to log function execution time.
    
    Args:
        func: Function to decorate.
        
    Returns:
        Decorated function with execution time logging.
    """
    import functools
    import time
    
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        logger = get_logger(func.__module__)
        start_time = time.time()
        
        try:
            logger.debug(f"Starting {func.__name__}")
            result = func(*args, **kwargs)
            execution_time = time.time() - start_time
            logger.debug(f"Completed {func.__name__} in {execution_time:.2f}s")
            return result
            
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"Failed {func.__name__} after {execution_time:.2f}s: {e}")
            raise
    
    return wrapper


def log_progress(total: int, description: str = "Processing"):
    """Context manager for logging progress of long-running operations.
    
    Args:
        total: Total number of items to process.
        description: Description of the operation.
        
    Yields:
        Function to call for each completed item.
    """
    import contextlib
    
    @contextlib.contextmanager
    def progress_context():
        logger = get_logger("progress")
        completed = 0
        
        def update_progress():
            nonlocal completed
            completed += 1
            if completed % max(1, total // 10) == 0 or completed == total:
                percentage = (completed / total) * 100
                logger.info(f"{description}: {completed}/{total} ({percentage:.1f}%)")
        
        logger.info(f"Starting {description}: 0/{total} (0.0%)")
        
        try:
            yield update_progress
        finally:
            if completed < total:
                logger.warning(f"{description} incomplete: {completed}/{total}")
            else:
                logger.info(f"{description} completed: {total}/{total} (100.0%)")
    
    return progress_context()