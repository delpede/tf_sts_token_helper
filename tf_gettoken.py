#!/usr/bin/env python3
try:
    import boto3
    import botocore
    from botocore.exceptions import ClientError
except ImportError as import_err:
    print(f'You need modules boto3 and botocore: {import_err}')
from pathlib import Path
from configparser import ConfigParser
from datetime import datetime
import os
import sys
import argparse
import shutil


def main():

    ## Configuration
    '''
        configure default arn and default profiles
    '''
    default_profile = 'netic-iam'
    default_profile_mfa = 'netic-iam-mfa'
    default_arn = ''
    default_duration = 43200

    parser = argparse.ArgumentParser(description='Pass values to AWS STS')
    parser.add_argument('--mfa_token', '-t',
                        type=int,
                        help='Token from your AWS Google Authenticatior')
    parser.add_argument('--profile', '-p',
                        type=str,
                        help='The AWS profile to use for authentication')
    parser.add_argument('--update', '-u',
                        type=str,
                        help='The profile you want to update with new token')
    parser.add_argument('--arn', '-a',
                        type=str,
                        help='AWS ARN for user account')
    parser.add_argument('--verbose', '-v',
                        action='store_true',
                        help='Verbose')
    parser.add_argument('--duration', '-d',
                        type=int,
                        help='How long before token expires in seconds (Default')

    args = parser.parse_args()

    if args.profile:
        profile = args.profile
    else:
        profile = default_profile

    if args.update:
        update_profile = args.update
    else:
        update_profile = default_profile_mfa

    if args.mfa_token:
        mfa_token = args.mfa_token
    else:
        mfa_token = int(input('Enter MFA Token for AWS Account: '))
        if len(str(mfa_token)) != 6:
            sys.exit("Not a valid MFA code")

    if args.arn:
        my_arn = args.arn
    else:
        my_arn = default_arn

    if args.duration:
        duration = args.duration
    else:
        duration = default_duration

    if args.verbose:
        set_verbose = True
    else:
        set_verbose = False

    get_sts_token(profile,
                  update_profile, 
                  mfa_token, 
                  my_arn, 
                  duration, 
                  set_verbose)


def get_sts_token(profile,
                  update_profile,
                  mfa_token, 
                  my_arn,
                  duration,  
                  set_verbose):

    aws_profile = profile
    aws_mfa_token = str(mfa_token)

    session = boto3.Session(profile_name=aws_profile)
    sts_client = session.client('sts')

    try:
        
        response = sts_client.get_session_token(
            DurationSeconds=duration,
            SerialNumber=my_arn,
            TokenCode=aws_mfa_token
        )

        root_response = response['Credentials']
        aws_access_key_id = root_response['AccessKeyId']
        aws_secret_access_key = root_response['SecretAccessKey']
        aws_session_token = root_response['SessionToken']

        if set_verbose is True:
            print(aws_access_key_id)
            print(aws_secret_access_key)
            print(aws_session_token)

    except ClientError as err:
        print(err)
    
    if backup_aws_configuarations(set_verbose) is True:
        update_aws_credentials(profile,
                                    update_profile, 
                                    aws_access_key_id,
                                    aws_secret_access_key,
                                    aws_session_token)
    else:
        sys.exit()


def backup_aws_configuarations(set_verbose):

    home = str(Path.home())
    aws_config_folder = home + '/' + '.aws/'
    aws_configs = ['config', 'credentials']
    backup_aws_config_folder = home + '/.tf_gettoken_backups/'
    timenow = datetime.now()
    formatted_time_now = timenow.strftime('%Y%m%d-%H%M%S')

    if not os.path.exists(backup_aws_config_folder):
        try:
            os.mkdir(backup_aws_config_folder)
            if set_verbose == True:
                print(f'Created backup folder: {backup_aws_config_folder}')
        except FileExistsError as err:
            if set_verbose == True:
                print(f'{err}')

    if os.path.exists(aws_config_folder):
        try:
            for aws_file in aws_configs:
                src_aws_file = aws_config_folder + aws_file
                backup_aws_File = backup_aws_config_folder + aws_file + '-' + formatted_time_now

                shutil.copyfile(src_aws_file, backup_aws_File)

            return True
        except shutil.Error as err:
            print(f'SHUTIL - AWS config folder not backed up {err}')
        except OSError as err:
            print(f'OSError - AWS config folder not backed up {err}')

    else:
        sys.exit(f'Folder {aws_config_folder} does not exists. Exit')


def update_aws_credentials(profile,
                            update_profile,
                            aws_access_key_id,
                            aws_secret_access_key,
                            aws_session_token):

    home = str(Path.home())
    aws_config_folder = home + '/' + '.aws/'
    aws_credentials = aws_config_folder + 'credentials'

    config_parser = ConfigParser()
    config_parser.read(aws_credentials)

    try:
        config_parser.set(update_profile, 'aws_access_key_id', aws_access_key_id)
        config_parser.set(update_profile, 'aws_secret_access_key', aws_secret_access_key)
        config_parser.set(update_profile, 'aws_session_token', aws_session_token)

        with open(aws_credentials, 'w') as update_file:
            config_parser.write(update_file)
        
        print('AWS Credentials file updated')

    except OSError as err:
        print(f'Config error: {err}')


if __name__ == '__main__':
    main()