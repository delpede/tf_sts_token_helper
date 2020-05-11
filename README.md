# tf_sts_token_helper
Script to help getting an sts token, and setting up profile


### Arguments

Help menu
````
--help, -h
`````

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
`````
--my_arn, -a
`````

Duration of the token in seconds
`````
--duration, -d
`````

Add verbosity to the execution
`````
--verbose, -v
`````

Script copies .aws/config and .aws/credentials to a folder called .tf_gettoken_backups before updating credential file

### Example
````
tf_gettoken.py --arn arn:aws:iam::111111111111:user --update profile-to-update --profile profile-to-use --mfa_token 111222 --duration 43600 --verbose
````

