import getpass

try:
    import configparser
    from configparser import NoOptionError, NoSectionError
except ImportError:
    import ConfigParser as configparser  # noqa
    from ConfigParser import NoOptionError, NoSectionError  # noqa

from awsmfa.util import log_error_and_exit, prompter


def initial_setup(logger, config, config_path):
    console_input = prompter()

    profile_name = console_input('Profile name to [%s]: ' % ("default"))
    if profile_name is None or profile_name == "":
        profile_name = "default"

    profile_name = "{}-long-term".format(profile_name)
    aws_access_key_id = getpass.getpass('aws_access_key_id: ')
    if aws_access_key_id is None or aws_access_key_id == "":
        log_error_and_exit(logger, "You must supply aws_access_key_id")
    aws_secret_access_key = getpass.getpass('aws_secret_access_key: ')
    if aws_secret_access_key is None or aws_secret_access_key == "":
        log_error_and_exit(logger, "You must supply aws_secret_access_key")

    config.add_section(profile_name)
    config.set(profile_name, 'aws_access_key_id', aws_access_key_id)
    config.set(profile_name, 'aws_secret_access_key', aws_secret_access_key)
    with open(config_path, 'w') as configfile:
        config.write(configfile)
