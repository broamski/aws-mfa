import argparse
try:
    import configparser
    from configparser import NoOptionError, NoSectionError
except ImportError:
    import ConfigParser as configparser
    from ConfigParser import NoOptionError, NoSectionError
import datetime
import getpass
import logging
import os
import sys
import boto3

from botocore.exceptions import ClientError, ParamValidationError
from awsmfa.config import initial_setup
from awsmfa.util import log_error_and_exit, prompter

logger = logging.getLogger('aws-mfa')

AWS_CREDS_PATH = '%s/.aws/credentials' % (os.path.expanduser('~'),)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--device',
                        required=False,
                        metavar='arn:aws:iam::123456788990:mfa/dudeman',
                        help="The MFA Device ARN. This value can also be "
                        "provided via the environment variable 'MFA_DEVICE' or"
                        " the ~/.aws/credentials variable 'aws_mfa_device'.")
    parser.add_argument('--duration',
                        type=int,
                        help="The duration, in seconds, that the temporary "
                             "credentials should remain valid. Minimum value: "
                             "900 (15 minutes). Maximum: 129600 (36 hours). "
                             "Defaults to 43200 (12 hours), or 3600 (one "
                             "hour) when using '--assume-role'. This value "
                             "can also be provided via the environment "
                             "variable 'MFA_STS_DURATION'. ")
    parser.add_argument('--profile',
                        help="If using profiles, specify the name here. The "
                        "default profile name is 'default'. The value can "
                        "also be provided via the environment variable "
                        "'AWS_PROFILE'.",
                        required=False)
    parser.add_argument('--long-term-suffix', '--long-suffix',
                        help="The suffix appended to the profile name to"
                        "identify the long term credential section",
                        required=False)
    parser.add_argument('--short-term-suffix', '--short-suffix',
                        help="The suffix appended to the profile name to"
                        "identify the short term credential section",
                        required=False)
    parser.add_argument('--assume-role', '--assume',
                        metavar='arn:aws:iam::123456788990:role/RoleName',
                        help="The ARN of the AWS IAM Role you would like to "
                        "assume, if specified. This value can also be provided"
                        " via the environment variable 'MFA_ASSUME_ROLE'",
                        required=False)
    parser.add_argument('--role-session-name',
                        help="Friendly session name required when using "
                        "--assume-role",
                        default=getpass.getuser(),
                        required=False)
    parser.add_argument('--force',
                        help="Refresh credentials even if currently valid.",
                        action="store_true",
                        required=False)
    parser.add_argument('--log-level',
                        help="Set log level",
                        choices=[
                            'CRITICAL', 'ERROR', 'WARNING',
                            'INFO', 'DEBUG', 'NOTSET'
                        ],
                        required=False,
                        default='DEBUG')
    parser.add_argument('--setup',
                        help="Setup a new log term credentials section",
                        action="store_true",
                        required=False)
    args = parser.parse_args()

    level = getattr(logging, args.log_level)
    setup_logger(level)

    if not os.path.isfile(AWS_CREDS_PATH):
        console_input = prompter()
        create = console_input("Could not locate credentials file at {}, "
                               "would you like to create one? "
                               "[y/n]".format(AWS_CREDS_PATH))
        if create.lower() == "y":
            with open(AWS_CREDS_PATH, 'a'):
                pass
        else:
            log_error_and_exit(logger, 'Could not locate credentials file at '
                               '%s' % (AWS_CREDS_PATH,))

    config = get_config(AWS_CREDS_PATH)

    if args.setup:
        initial_setup(logger, config, AWS_CREDS_PATH)
        return

    validate(args, config)


def get_config(aws_creds_path):
    config = configparser.RawConfigParser()
    try:
        config.read(aws_creds_path)
    except configparser.ParsingError:
        e = sys.exc_info()[1]
        log_error_and_exit(logger, "There was a problem reading or parsing "
                           "your credentials file: %s" % (e.args[0],))
    return config


def validate(args, config):
    if not args.profile:
        if os.environ.get('AWS_PROFILE'):
            args.profile = os.environ.get('AWS_PROFILE')
        else:
            args.profile = 'default'

    if not args.long_term_suffix:
        long_term_name = '%s-long-term' % (args.profile,)
    elif args.long_term_suffix.lower() == 'none':
        long_term_name = args.profile
    else:
        long_term_name = '%s-%s' % (args.profile, args.long_term_suffix)

    if not args.short_term_suffix or args.short_term_suffix.lower() == 'none':
        short_term_name = args.profile
    else:
        short_term_name = '%s-%s' % (args.profile, args.short_term_suffix)

    if long_term_name == short_term_name:
        log_error_and_exit(logger,
                           "The value for '--long-term-suffix' cannot "
                           "be equal to the value for '--short-term-suffix'")

    if args.assume_role:
        role_msg = "with assumed role: %s" % (args.assume_role,)
    elif config.has_option(args.profile, 'assumed_role_arn'):
        role_msg = "with assumed role: %s" % (
            config.get(args.profile, 'assumed_role_arn'))
    else:
        role_msg = ""
    logger.info('Validating credentials for profile: %s %s' %
                (short_term_name, role_msg))
    reup_message = "Obtaining credentials for a new role or profile."

    try:
        key_id = config.get(long_term_name, 'aws_access_key_id')
        access_key = config.get(long_term_name, 'aws_secret_access_key')
    except NoSectionError:
        log_error_and_exit(logger,
                           "Long term credentials session '[%s]' is missing. "
                           "You must add this section to your credentials file "
                           "along with your long term 'aws_access_key_id' and "
                           "'aws_secret_access_key'" % (long_term_name,))
    except NoOptionError as e:
        log_error_and_exit(logger, e)

    # get device from param, env var or config
    if not args.device:
        if os.environ.get('MFA_DEVICE'):
            args.device = os.environ.get('MFA_DEVICE')
        elif config.has_option(long_term_name, 'aws_mfa_device'):
            args.device = config.get(long_term_name, 'aws_mfa_device')
        else:
            log_error_and_exit(logger,
                               'You must provide --device or MFA_DEVICE or set '
                               '"aws_mfa_device" in ".aws/credentials"')

    # get assume_role from param or env var
    if not args.assume_role:
        if os.environ.get('MFA_ASSUME_ROLE'):
            args.assume_role = os.environ.get('MFA_ASSUME_ROLE')
        elif config.has_option(long_term_name, 'assume_role'):
            args.assume_role = config.get(long_term_name, 'assume_role')

    # get duration from param, env var or set default
    if not args.duration:
        if os.environ.get('MFA_STS_DURATION'):
            args.duration = int(os.environ.get('MFA_STS_DURATION'))
        else:
            args.duration = 3600 if args.assume_role else 43200

    # If this is False, only refresh credentials if expired. Otherwise
    # always refresh.
    force_refresh = False

    # Validate presence of short-term section
    if not config.has_section(short_term_name):
        logger.info("Short term credentials section %s is missing, "
                    "obtaining new credentials." % (short_term_name,))
        if short_term_name == 'default':
            try:
                config.add_section(short_term_name)
            # a hack for creating a section named "default"
            except ValueError:
                configparser.DEFAULTSECT = short_term_name
                config.set(short_term_name, 'CREATE', 'TEST')
                config.remove_option(short_term_name, 'CREATE')
        else:
            config.add_section(short_term_name)
        force_refresh = True
    # Validate option integrity of short-term section
    else:
        required_options = ['assumed_role',
                            'aws_access_key_id', 'aws_secret_access_key',
                            'aws_session_token', 'aws_security_token',
                            'expiration']
        try:
            short_term = {}
            for option in required_options:
                short_term[option] = config.get(short_term_name, option)
        except NoOptionError:
            logger.warn("Your existing credentials are missing or invalid, "
                        "obtaining new credentials.")
            force_refresh = True

        try:
            current_role = config.get(short_term_name, 'assumed_role_arn')
        except NoOptionError:
            current_role = None

        if args.force:
            logger.info("Forcing refresh of credentials.")
            force_refresh = True
        # There are not credentials for an assumed role,
        # but the user is trying to assume one
        elif current_role is None and args.assume_role:
            logger.info(reup_message)
            force_refresh = True
        # There are current credentials for a role and
        # the role arn being provided is the same.
        elif (current_role is not None and
                args.assume_role and current_role == args.assume_role):
            pass
        # There are credentials for a current role and the role
        # that is attempting to be assumed is different
        elif (current_role is not None and
              args.assume_role and current_role != args.assume_role):
            logger.info(reup_message)
            force_refresh = True
        # There are credentials for a current role and no role arn is
        # being supplied
        elif current_role is not None and args.assume_role is None:
            logger.info(reup_message)
            force_refresh = True

    should_refresh = True

    # Unless we're forcing a refresh, check expiration.
    if not force_refresh:
        exp = datetime.datetime.strptime(
            config.get(short_term_name, 'expiration'), '%Y-%m-%d %H:%M:%S')
        diff = exp - datetime.datetime.utcnow()
        if diff.total_seconds() <= 0:
            logger.info("Your credentials have expired, renewing.")
        else:
            should_refresh = False
            logger.info(
                "Your credentials are still valid for %s seconds"
                " they will expire at %s"
                % (diff.total_seconds(), exp))

    if should_refresh:
        get_credentials(short_term_name, key_id, access_key, args, config)


def get_credentials(short_term_name, lt_key_id, lt_access_key, args, config):
    console_input = prompter()
    mfa_token = console_input('Enter AWS MFA code for device [%s] '
                              '(renewing for %s seconds):' %
                              (args.device, args.duration))

    client = boto3.client(
        'sts',
        aws_access_key_id=lt_key_id,
        aws_secret_access_key=lt_access_key
    )

    if args.assume_role:

        logger.info("Assuming Role - Profile: %s, Role: %s, Duration: %s",
                    short_term_name, args.assume_role, args.duration)
        if args.role_session_name is None:
            log_error_and_exit(logger, "You must specify a role session name "
                               "via --role-session-name")

        try:
            response = client.assume_role(
                RoleArn=args.assume_role,
                RoleSessionName=args.role_session_name,
                DurationSeconds=args.duration,
                SerialNumber=args.device,
                TokenCode=mfa_token
            )
        except ClientError as e:
            log_error_and_exit(logger,
                               "An error occured while calling "
                               "assume role: {}".format(e))
        except ParamValidationError:
            log_error_and_exit(logger, "Token must be six digits")

        config.set(
            short_term_name,
            'assumed_role',
            'True',
        )
        config.set(
            short_term_name,
            'assumed_role_arn',
            args.assume_role,
        )
    else:
        logger.info("Fetching Credentials - Profile: %s, Duration: %s",
                    short_term_name, args.duration)
        try:
            response = client.get_session_token(
                DurationSeconds=args.duration,
                SerialNumber=args.device,
                TokenCode=mfa_token
            )
        except ClientError as e:
            log_error_and_exit(
                logger,
                "An error occured while calling assume role: {}".format(e))
        except ParamValidationError:
            log_error_and_exit(
                logger,
                "Token must be six digits")

        config.set(
            short_term_name,
            'assumed_role',
            'False',
        )
        config.remove_option(short_term_name, 'assumed_role_arn')

    # aws_session_token and aws_security_token are both added
    # to support boto and boto3
    options = [
        ('aws_access_key_id', 'AccessKeyId'),
        ('aws_secret_access_key', 'SecretAccessKey'),
        ('aws_session_token', 'SessionToken'),
        ('aws_security_token', 'SessionToken'),
    ]

    for option, value in options:
        config.set(
            short_term_name,
            option,
            response['Credentials'][value]
        )
    # Save expiration individiually, so it can be manipulated
    config.set(
        short_term_name,
        'expiration',
        response['Credentials']['Expiration'].strftime('%Y-%m-%d %H:%M:%S')
    )
    with open(AWS_CREDS_PATH, 'w') as configfile:
        config.write(configfile)
    logger.info(
        "Success! Your credentials will expire in %s seconds at: %s"
        % (args.duration, response['Credentials']['Expiration']))
    sys.exit(0)


def setup_logger(level=logging.DEBUG):
    stdout_handler = logging.StreamHandler(stream=sys.stdout)
    stdout_handler.setFormatter(
        logging.Formatter('%(levelname)s - %(message)s'))
    stdout_handler.setLevel(level)
    logger.addHandler(stdout_handler)
    logger.setLevel(level)


if __name__ == "__main__":
    main()
