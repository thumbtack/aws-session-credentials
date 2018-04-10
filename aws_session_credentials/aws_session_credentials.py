'''
This script gets a set of AWS credentials that allows AWS IAM users to make AWS
API calls that are authenticated with an MFA device. This script requires an
MFA device to already be configured for an individual's AWS IAM user account
and for an API key pair to already exist on the system for that user account.

This script outputs shell commands that can be evaluated in the calling shell
(this is the recommended method of invocation). By default, this script runs in
env mode, and will provide the credentials as environment variables. The -c
flag will tell the script to instead write the credentials to the given AWS
credentials file (typically located at ~/.aws/credentials) and provide the
config profile as an environment variable. All official AWS libraries and tools
support reading the credentials from this script in either format.

Running the script in the default env mode with no existing session credentials
looks like this:

    $ echo $AWS_ACCESS_KEY_ID
    XXXXXXXXXXXXXXXXXXXX
    $ eval $(aws-session-credentials 654321123456 myusername)
    Enter device token: 938712
    $ echo $AWS_ACCESS_KEY_ID
    YYYYYYYYYYYYYYYYYYYY

Running the script in config mode with no existing session credentials looks
like this:

    $ echo $AWS_ACCESS_KEY_ID
    XXXXXXXXXXXXXXXXXXXX
    $ eval $(aws-session-credentials -c ~/.aws/credentials 654321123456 myusername)
    Enter device token: 938712
    $ echo $AWS_ACCESS_KEY_ID
    $ echo $AWS_PROFILE
    aws_session_credentials

Running the script in either mode with non-expired session credentials already
cached will skip the device token prompt and output the correct shell commands
without waiting on user input, unless the -f flag is specified, in which case
the script will forcibly get a new set of session credentials no matter the
current state of the system.

This script supports a non-interactive mode with the -n flag. This mode will
not ask for a device token, and thus will not update session credentials, even
if session credentials are missing or expired.

Hardware MFA devices are supported through the -s flag. Failing to provide the
-s flag while attempting to use a hardware MFA device will result in errors.

Running the script non-interactively with expiring credentials looks like this:

    $ eval $(aws-session-credentials -n 654321123456 myusername)
    AWS credentials are expiring soon
    Please run the credentials script interactively
    $ echo $AWS_ACCESS_KEY_ID
    YYYYYYYYYYYYYYYYYYYY

This script exits non-zero on failure.
'''

import argparse
try:
    import ConfigParser
except ImportError:
    import configparser
    ConfigParser = configparser
import datetime
import json
import os
import shutil
import sys
import boto3
import botocore

CACHE_FILENAME = os.path.expanduser('~/.aws_session_credentials')
CONFIG_SECTION = 'aws_session_credentials'
PROFILE_BKP = 'AWS_PROFILE_ASC'
EXPIRATION_BUFFER = 60 * 60 * 12  # seconds
SESSION_DURATION = 60 * 60 * 36  # seconds
TIME_FORMAT = '%Y-%m-%dT%H:%M:%S'


class MainException(Exception):
    '''An exception that wraps execution information'''
    def __init__(self, message, interactive):
        super(MainException, self).__init__(message)
        self.message = message
        self.interactive = interactive


def is_expired(date):
    '''Determine if a date has expired'''
    padding = datetime.timedelta(seconds=EXPIRATION_BUFFER)
    return datetime.datetime.now() > (date - padding)


def dump_credentials_to_file(credentials, credentials_file):
    '''Save credentials to an aws credentials file'''
    config = ConfigParser.ConfigParser()
    try:
        config.read(credentials_file)
    except ConfigParser.Error:
        raise MainException(
            'Malformed credentials file: {}'.format(credentials_file), True
        )
    config.remove_section(CONFIG_SECTION)
    config.add_section(CONFIG_SECTION)
    config.set(CONFIG_SECTION, 'aws_access_key_id', credentials['AccessKeyId'])
    config.set(CONFIG_SECTION, 'aws_secret_access_key', credentials['SecretAccessKey'])
    config.set(CONFIG_SECTION, 'aws_session_token', credentials['SessionToken'])
    if os.path.exists(credentials_file):
        shutil.copyfile(credentials_file, '{}.bkp'.format(credentials_file))
    with open(credentials_file, 'w') as handle:
        config.write(handle)


def dump_credentials(credentials, credentials_file, aws_profile):
    '''Save session credentials locally'''
    # save the session credentials locally
    credentials = credentials.copy()
    credentials['Expiration'] = credentials['Expiration'].strftime(TIME_FORMAT)
    with open(CACHE_FILENAME, 'w') as handle:
        json.dump(credentials, handle)
    # either update the AWS credentials file or set environment variables
    # these are mutually exclusive since having the environment variables set
    # means that the credentials file will never be read
    # pylint: disable=superfluous-parens
    if credentials_file is not None:
        dump_credentials_to_file(credentials, credentials_file)
        print('unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN;')
        print('export AWS_PROFILE={};'.format(CONFIG_SECTION))
    else:
        print('export AWS_ACCESS_KEY_ID={}'.format(credentials['AccessKeyId']))
        print('export AWS_SECRET_ACCESS_KEY={}'.format(credentials['SecretAccessKey']))
        print('export AWS_SESSION_TOKEN={}'.format(credentials['SessionToken']))
    # save a backup of the credentials profile
    print('unset {};'.format(PROFILE_BKP))
    if aws_profile:
        print('export {}={};'.format(PROFILE_BKP, aws_profile))


def load_credentials():
    '''Load the local session credentials if they exist'''
    try:
        with open(CACHE_FILENAME, 'r') as handle:
            credentials = json.load(handle)
    except EnvironmentError:
        return None
    try:
        credentials['Expiration'] = datetime.datetime.strptime(
            credentials['Expiration'], TIME_FORMAT
        )
    except (KeyError, ValueError):
        return None
    return credentials


def load_permanent_credentials(aws_profile):
    '''Load permanent user credentials if they can be found'''
    resolver = botocore.credentials.create_credential_resolver(
        botocore.session.Session(
            profile=(aws_profile or 'default')
        )
    )
    # find the first provider that doesn't provide session credentials
    for provider in resolver.providers:
        credentials = provider.load()
        if credentials is not None:
            credentials = credentials.get_frozen_credentials()
            if credentials.token is None:
                return (credentials.access_key, credentials.secret_key)
    # nothing found
    raise MainException('Could not find permanent credentials', True)


def fetch_credentials(account, user, serial, aws_profile):
    '''Get a set of AWS session credentials'''
    # read the MFA token from the user
    sys.stderr.write('Enter AWS MFA device token [6-digit number]: ')
    try:
        token = raw_input()
    except NameError:
        token = input()
    # get a set of permanent credentials with which to make the request
    # this should occur after user input to prevent a gap
    # between calculating the correct credentials and using them
    # in case they change in the meantime
    permanent_credentials = load_permanent_credentials(aws_profile)
    client = boto3.client(
        'sts',
        aws_access_key_id=permanent_credentials[0],
        aws_secret_access_key=permanent_credentials[1],
    )
    # request session credentials from aws
    if not serial:
        serial = 'arn:aws:iam::{}:mfa/{}'.format(account, user)
    try:
        credentials = client.get_session_token(
            DurationSeconds=SESSION_DURATION,
            SerialNumber=serial,
            TokenCode=token,
        )['Credentials']
    except Exception as err:
        raise MainException(str(err).replace('\n', ' '), True)
    return credentials


def parse_args():
    '''Parse the CLI arguments'''
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        '--non-interactive', '-n',
        action='store_true',
        help='do not update credentials from aws',
    )
    parser.add_argument(
        '--credentials-file', '-c',
        help='persist credentials in the given credentials file',
    )
    parser.add_argument(
        '--serial', '-s', default=None,
        help='use the given hardware device to authenticate',
    )
    parser.add_argument(
        '--force', '-f',
        action='store_true',
        help='get a new set of credentials no matter what'
    )
    parser.add_argument('ACCOUNT', help='AWS account id')
    parser.add_argument('USER', help='AWS IAM user name')
    return parser.parse_args()


def run(account, user, interactive, credentials_file, serial, force):
    '''Run the program'''
    # get the non-session aws credentials profile if one exists
    aws_profile = os.getenv('AWS_PROFILE')
    if aws_profile == CONFIG_SECTION:
        aws_profile = os.getenv(PROFILE_BKP)
        # it's impossible to use the temporary session to get a new session
        del os.environ['AWS_PROFILE']
    # load the cached credentials
    credentials = load_credentials()
    exist = credentials is not None
    expired = exist and is_expired(credentials['Expiration'])
    # handle the current state of the credentials
    if interactive and (not exist or expired or force):
        credentials = fetch_credentials(account, user, serial, aws_profile)
    elif not exist:
        raise MainException('AWS credentials are missing', False)
    elif expired:
        raise MainException('AWS credentials are expiring soon', False)
    elif force:
        raise MainException('Force-update requested', False)
    # dump the credentials if they exist
    if credentials is not None:
        dump_credentials(credentials, credentials_file, aws_profile)


def main():
    '''Execute the script'''
    args = parse_args()
    try:
        run(
            args.ACCOUNT,
            args.USER,
            not args.non_interactive,
            args.credentials_file,
            args.serial,
            args.force,
        )
    except MainException as err:
        sys.stderr.write('{}\n'.format(err.message))
        if err.interactive:
            sys.exit(1)
        sys.stderr.write('Please run the credentials script interactively\n')
