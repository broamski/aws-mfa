import sys

__version__ = "0.0.1"

LOGO_TEMPLATE = f"""
impersonating the (seemingly) dead aws-mfa as

███╗   ███╗███████╗ █████╗ ██╗  ██╗ █████╗ ██╗    ██╗███████╗
████╗ ████║██╔════╝██╔══██╗██║  ██║██╔══██╗██║    ██║██╔════╝
██╔████╔██║█████╗  ███████║███████║███████║██║ █╗ ██║███████╗
██║╚██╔╝██║██╔══╝  ██╔══██║╚════██║██╔══██║██║███╗██║╚════██║
██║ ╚═╝ ██║██║     ██║  ██║     ██║██║  ██║╚███╔███╔╝███████║
╚═╝     ╚═╝╚═╝     ╚═╝  ╚═╝     ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝
v{__version__} by baduker
"""

def show_logo():
    print(LOGO_TEMPLATE)

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
