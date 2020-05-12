# tf_sts_token_helper
Script to help getting an sts token, and setting up profile

### Docs
We use one AWS account, that can switch to other accounts. We have at least two AWS profiles

.aws/config
````
[default]
region = eu-west-1
output = json

[profile netic-iam]
region = eu-west-1
output = json

````

.aws/credentials
````
[netic-iam]
aws_access_key_id = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
aws_secret_access_key = xxxxxxxxxxxxxxxxxxxxxxxxxxxxx

[netic-iam-mfa]
aws_access_key_id = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
aws_secret_access_key = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
aws_session_token = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx


````

The scripts updates the credentials in netic-iam-mfa. We then source that profile in other profiles we would like to use.

````
[profile other-prod]
role_arn = arn:aws:iam::1111111111111:role/netic-iam
source_profile = netic-iam-mfa
region = eu-west-1
````

### Configuration
Configure default values in main()

### Arguments

Help menu
````
--help, -h
````

Your google authentication token
````
--mfa_token, -m
````

The AWS Profile to use
````
--profile, -p
````

The Profile you want to add the new Token to
````
--update, -u
````

Arn of the main account user
````
--my_arn, -a
````

Duration of the token in seconds
````
--duration, -d
````

Add verbosity to the execution
````
--verbose, -v
````

Script copies .aws/config and .aws/credentials to a folder called .tf_gettoken_backups before updating credential file


### Usage

If you just execute the script, it will ask for MFA token. You can override values for arn, profiles and duration, with commandline parameters.

Default usage
````
tf_gettoken.py
````

Override with arguments.
````
tf_gettoken.py --arn arn:aws:iam::111111111111:user --update profile-to-update --profile profile-to-use --mfa_token 111222 --duration 43600 --verbose
````

