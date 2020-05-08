#!/usr/bin/env python3

import boto3
import botocore
from botocore.exceptions import ClientError
import os
import sys
import argparse

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


def get_sts_token(profile, mfa_token, my_arn):

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

        print(aws_access_key_id)
        print(aws_secret_access_key)
        print(aws_session_token)

    except ClientError as err:
        print(err)


def 


get_sts_token(profile, mfa_token, my_arn)