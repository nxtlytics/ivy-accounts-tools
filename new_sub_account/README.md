# Create new AWS Account

## How to use it

```
$ cd path/to/this/repo
$ AWS_PROFILE=profile-to-use pipenv run python new_sub_account/new_sub_account.py --help
usage: new_sub_account.py [-h] -a SUB_ACCOUNT_NAME -e EMAIL [-l {CRITICAL,ERROR,WARNING,INFO,DEBUG}]

Creates new AWS sub-account

optional arguments:
  -h, --help            show this help message and exit
  -a SUB_ACCOUNT_NAME, --sub-account-name SUB_ACCOUNT_NAME
                        AWS Sub Account Name
  -e EMAIL, --e-mail EMAIL
                        E-Mail address for the AWS Sub Account
  -l {CRITICAL,ERROR,WARNING,INFO,DEBUG}, --log-level {CRITICAL,ERROR,WARNING,INFO,DEBUG}
                        Set the logging output level
```
