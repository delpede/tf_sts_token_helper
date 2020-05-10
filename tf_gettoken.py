#!/usr/bin/env python3
try:
    import boto3
    import botocore
    from botocore.exceptions import ClientError
except ImportError as import_err:
    print(f'You ned modules boto3 and botocore: {import_err}')
from pathlib import Path
from configparser import SafeConfigParser
import os
import sys
import argparse
import shutil

def main():
    parser = argparse.ArgumentParser(description='Pass values to AWS STS')
    parser.add_argument('--mfa_token', '-t',
                        type=int,
                        help='Token from your AWS Google Authenticatior')
    parser.add_argument('--profile', '-p',
                        type=str,
                        help='The AWS profile to use for authentication')
    parser.add_argument('--arn', '-a',
                        type=str,
                        help='AWS ARN for user account')
    parser.add_argument('--verbose', '-v',
                        action='store_true',
                        help='Verbose')

    args = parser.parse_args()

    if args.profile:
        profile = args.profile
    else:
        profile = input('What profile to use (empty for default): ')
        if profile == '':
            profile = 'netic-iam'

    if args.mfa_token:
        mfa_token = args.mfa_token
    else:
        mfa_token = int(input('Enter MFA Token for AWS Account: '))
        if len(str(mfa_token)) != 6:
            sys.exit("Not a valid MFA code")

    if args.arn:
        my_arn = args.arn
    else:
        my_arn = ''

    if args.verbose:
        set_verbose = True
    else:
        set_verbose = False

    get_sts_token(profile, mfa_token, my_arn, set_verbose)


def get_sts_token(profile, 
                  mfa_token, 
                  my_arn, 
                  set_verbose):

    aws_profile = profile
    aws_mfa_token = str(mfa_token)

    session = boto3.Session(profile_name=aws_profile)
    sts_client = session.client('sts')

    try:
        
        response = sts_client.get_session_token(
            DurationSeconds=43200,
            SerialNumber=my_arn,
            TokenCode=aws_mfa_token
        )

        root_response = response['Credentials']
        aws_access_key_id = root_response['AccessKeyId']
        aws_secret_access_key = root_response['SecretAccessKey']
        aws_session_token = root_response['SessionToken']

        if set_verbose == True:
            print(aws_access_key_id)
            print(aws_secret_access_key)
            print(aws_session_token)

    except ClientError as err:
        print(err)

    update_aws_credentials(profile, 
                                aws_access_key_id,
                                aws_secret_access_key,
                                aws_session_token)


def backup_aws_configuarations():

    home = str(Path.home())
    aws_config_folder = home + '/' + '.aws'
    if os.path.exists(aws_config_folder):
        try:
            aws_config_folder_backup = aws_config_folder + '-backup'
            shutil.copytree(aws_config_folder, aws_config_folder_backup)

            return True
        except shutil.Error as err:
            print(f'AWS confif folder not backed up {err}')
        except OSError as err:
            print(f'AWS confif folder not backed up {err}')

    else:
        sys.exit(f'Folder {aws_config_folder} does not exists. Exit')


def update_aws_credentials(profile, 
                            aws_access_key_id,
                            aws_secret_access_key,
                            aws_session_token):

    home = str(Path.home())
    aws_config_folder = home + '/' + '.aws/'
    aws_credentials = aws_config_folder + 'credentials'

    config_parser = SafeConfigParser()
    config_parser.read(aws_credentials)

    try:
        config_parser.update(profile, aws_access_key_id)
        config_parser.update(profile, aws_secret_access_key)
        config_parser.update(profile, aws_session_token)
    except OSError as err:
        print(f'Config error: {err}')


if __name__ == '__main__':
    main()