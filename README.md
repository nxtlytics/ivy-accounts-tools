# Multiple tools used when creating new accounts

## Creating a new AWS account

- SEE [Ivy Docs](https://github.com/nxtlytics/ivy-documentation/blob/master/howto/Processes/Creating_new_AWS_GovCloud_accounts.md) INSTEAD!

### How to use

```bash
$ AWS_PROFILE=awsprofile pipenv run python setup_account.py --help
usage: setup_account.py [-h] -a SUB_ACCOUNT_NAME -f SAML_FILE [-s SAML_PROVIDER] [-e EMAIL] [-t IVY_TAG] [-l {CRITICAL,ERROR,WARNING,INFO,DEBUG}]

1. Creates new sub-account, if email is provided 2. Removes default VPCs 3. Sets account alias 4. Configures SAML 5. Creates default roles and allows access via SAML only

optional arguments:
  -h, --help            show this help message and exit
  -a SUB_ACCOUNT_NAME, --sub-account-name SUB_ACCOUNT_NAME
                        AWS Sub Account Name
  -f SAML_FILE, --saml-metadata-document-file SAML_FILE
                        Path to An XML document generated by an identity provider (IdP) that supports SAML 2.0
  -s SAML_PROVIDER, --saml-provider-name SAML_PROVIDER
                        Name of the saml provider. Examples: gsuite, msft
  -e EMAIL, --e-mail EMAIL
                        E-Mail address for the AWS Sub Account
  -t IVY_TAG, --ivy-tag IVY_TAG
                        Ivy tag also known as namespace
  -l {CRITICAL,ERROR,WARNING,INFO,DEBUG}, --log-level {CRITICAL,ERROR,WARNING,INFO,DEBUG}
                        Set the logging output level
```
