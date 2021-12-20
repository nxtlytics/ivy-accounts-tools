# Multiple tools used when creating new accounts

## Creating a new AWS account

- SEE [Ivy Docs](https://github.com/nxtlytics/ivy-documentation/blob/master/howto/Processes/Creating_new_AWS_subaccount.md) INSTEAD!

### How to use

```bash
$ AWS_PROFILE=awsprofile pipenv run python setup_account.py --help
usage: setup_account.py [-h] -a ACCOUNT_NAME -f SAML_FILE [-s SAML_PROVIDER] -c PHASE -p PURPOSE [-r REGIONS] [-e EMAIL] [-t IVY_TAG] [-l {CRITICAL,ERROR,WARNING,INFO,DEBUG}]

1. Creates new sub-account, if email is provided 2. Removes default VPCs 3. Sets account alias 4. Configures SAML 5. Creates default roles and allows access via SAML only

optional arguments:
  -h, --help            show this help message and exit
  -a ACCOUNT_NAME, --account-name ACCOUNT_NAME
                        AWS Account Name and alias
  -f SAML_FILE, --saml-metadata-document-file SAML_FILE
                        Path to An XML document generated by an identity provider (IdP) that supports SAML 2.0
  -s SAML_PROVIDER, --saml-provider-name SAML_PROVIDER
                        Name of the saml provider. Examples: gsuite, azuread
  -c PHASE, --phase PHASE
                        AWS Sub Account Phase (prod, dev, stage, ...)
  -p PURPOSE, --purpose PURPOSE
                        AWS Sub Account purpose (app, tools, sandbox, ...)
  -r REGIONS, --regions REGIONS
                        Comma-separated list of AWS regions
  -e EMAIL, --e-mail EMAIL
                        E-Mail address for the AWS Sub Account
  -t IVY_TAG, --ivy-tag IVY_TAG
                        Ivy tag also known as namespace
  -l {CRITICAL,ERROR,WARNING,INFO,DEBUG}, --log-level {CRITICAL,ERROR,WARNING,INFO,DEBUG}
                        Set the logging output level
```

### How to test

```bash
./run_tests.sh
...
collected 3 items

tests/test_setup_account.py::test_sub_account_creation PASSED
tests/test_setup_account.py::test_sub_account_duplicate PASSED
tests/test_setup_account.py::test_account_setup PASSED
tests/test_setup_account.py::test_account_alias_duplicate PASSED
tests/test_setup_account.py::test_vpc_cleaner PASSED
...
---------- coverage: platform darwin, python 3.8.4-final-0 -----------
Name                                 Stmts   Miss  Cover
--------------------------------------------------------
new_sub_account/new_sub_account.py      81     30    63%
setup_account.py                        44     44     0%
setup_sso/setup_sso.py                 110     32    71%
tests/test_setup_account.py             65      0   100%
vpc_cleaner/vpc_cleaner.py             154     35    77%
--------------------------------------------------------
TOTAL                                  454    141    69%

...
```
