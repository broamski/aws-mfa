import sys


def log_error_and_exit(logger, message):
    """Log an error message and exit with error"""
    logger.error(message)
    sys.exit(1)


def prompter():
    try:
        console_input = raw_input
    except NameError:
        console_input = input

    return console_input
