# Creating a new commercial AWS subaccount

1.  Retrieve IAM credentials for commercial organization payer
    commercial account and set them up in your `~/.aws/credentials`
    and/or `~/.aws/config`

2.  Retrieve the SAML Document from your Identity Provider (IDP)

    **References:**
    - [G Suite - How to setup custom SAML application](https://support.google.com/a/answer/6087519?hl=en)
    - [AzureAD SSO with AWS](https://docs.microsoft.com/en-us/azure/active-directory/saas-apps/amazon-web-service-tutorial)

3.  Clone https://github.com/Over-haul/cloud-accounts-tools and setup [poetry](https://github.com/python-poetry/poetry)

``` bash
git clone git@github.com:Over-haul/cloud-accounts-tools.git
```

or

```bash
git clone https://github.com/Over-haul/cloud-accounts-tools.git
```

4.  Create a new sub account

``` bash
AWS_PROFILE=regular-aws poetry run python setup_account.py -a <accountname> -e infeng+<accountname>@example.com \
    -f </path/to/saml/document.xml> -s <SAML_PROVIDER, defaults to gsuite> -t <--tag-prefix, defaults to thunder> \
    [-l {CRITICAL,ERROR,WARNING,INFO,DEBUG}]
```

**Example Output:**

``` bash
$ AWS_PROFILE=master-account pipenv run python setup_account.py \
    -a thunder-aws-app-dev -e infeng+thunder-aws-app-dev@example.com \
    -s gsuite -t thunder -f ./gsuite_metadata.xml
2020-09-17 14:51:56,364 INFO (MainThread) [botocore.credentials] Found credentials in shared credentials file: ~/.aws/credentials
2020-09-17 14:51:56,444 INFO (MainThread) [root] I will try to create sub-account thunder-aws-app-dev
2020-09-17 14:51:57,023 INFO (MainThread) [new_sub_account.new_sub_account] An account with name thunder-aws-app-dev and/or email infeng+thunder-aws-app-dev@example.com already exists, its account ID is 000000000000
2020-09-17 14:51:57,023 INFO (MainThread) [new_sub_account.new_sub_account] No sub account will be created
2020-09-17 14:51:57,496 INFO (MainThread) [setup_sso.setup_sso] An account alias thunder-aws-app-dev already exists
2020-09-17 14:51:57,496 INFO (MainThread) [setup_sso.setup_sso] Account alias has already been setup and is thunder-aws-app-dev
2020-09-17 14:51:58,431 INFO (MainThread) [vpc_cleaner.vpc_cleaner] Cleaning AWS region [eu-north-1] of all VPCs...
2020-09-17 14:51:59,502 INFO (MainThread) [vpc_cleaner.vpc_cleaner] Cleaning VPC [vpc-00000000] in region [eu-north-1]
2020-09-17 14:51:59,531 INFO (MainThread) [botocore.credentials] Found credentials in shared credentials file: ~/.aws/credentials
2020-09-17 14:51:59,588 INFO (MainThread) [vpc_cleaner.vpc_cleaner] Running step [del_igw] for VPC [vpc-00000000] in region [eu-north-1]
2020-09-17 14:52:00,377 INFO (MainThread) [vpc_cleaner.vpc_cleaner] Running step [del_sub] for VPC [vpc-00000000] in region [eu-north-1]
2020-09-17 14:52:00,672 INFO (MainThread) [vpc_cleaner.vpc_cleaner] Running step [del_rtb] for VPC [vpc-00000000] in region [eu-north-1]
2020-09-17 14:52:00,905 INFO (MainThread) [vpc_cleaner.vpc_cleaner] Running step [del_acl] for VPC [vpc-00000000] in region [eu-north-1]
2020-09-17 14:52:01,137 INFO (MainThread) [vpc_cleaner.vpc_cleaner] Running step [del_sgp] for VPC [vpc-00000000] in region [eu-north-1]
2020-09-17 14:52:01,377 INFO (MainThread) [vpc_cleaner.vpc_cleaner] Running step [del_vpc] for VPC [vpc-00000000] in region [eu-north-1]
...
```


5.  Add the commercial SSO role to users

  a) G Suite Instructions

    1.  Open G Suite Admin

    2.  Users -> select user to edit -> User Information -> **AWS SSO**

    3.  Add `arn:aws:iam::<new account id>:role/SSOAdministratorAccess,arn:aws:iam::<new account id>:saml-provider/<TAG_PREFIX>-<SAML_PROVIDER>` or `arn:aws:iam::<new account id>:role/SSOViewOnlyAccess,arn:aws:iam::<new account id>:saml-provider/<TAG_PREFIX>-<SAML_PROVIDER>` (accordingly)

    4.  Ensure duration is set to **28800**

    5.  Rinse and repeat for all users that require access to new account

  b) AzureAD Instructions

    1.  Open `App Role | Preview` for `Amazon Web Services (AWS)`, the trick is to update the following URL with the Application ID and open it in a browser tab `https://aad.portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/AppRoles/appId/<Insert Application ID here>/isMSAApp/`

    2.  Click `Create App Role` -> Enter `Display Name` e.g. `<SysEnv name> <Role Name>` -> Select `Users/Groups` for `Allowed member types` -> Enter `arn:aws:iam::<new account id>:role/SSOAdministratorAccess,arn:aws:iam::<new account id>:saml-provider/<TAG_PREFIX>-<SAML_PROVIDER>` for `Value` -> Enter whatever you deem appropriate for `Description`

    3.  Repeat step 2 but enter `arn:aws:iam::<new account id>:role/SSOViewOnlyAccess,arn:aws:iam::<new account id>:saml-provider/<TAG_PREFIX>-<SAML_PROVIDER>` for `Value`

    4.  Go back to list your [Enterprise Applications](https://aad.portal.azure.com/#blade/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/AllApps) -> Click `Amazon Web Services (AWS)` -> Click `Users and groups` -> Click `Add User` -> Click `Users` -> Search and select all users you want to have Administrator access -> Click `Select` at the bottom right side of the screen -> Click `Select Role` and click the `Display Name` you gave to the Administrator role

    5.  Repeat step 4 but now select the `Users` you want to have View Only access

6.  if you use [saml2aws](https://github.com/Versent/saml2aws), configure local SAML credentials for new commercial account. Add the following to your **`~/.saml2aws`** configuration file:

  a) G Suite

``` text
[<new account name>]
app_id               =
url                  = <URL from G Suite's SAML>
username             = <you>@example.com
provider             = GoogleApps
mfa                  = Auto
skip_verify          = false
timeout              = 0
aws_urn              = urn:amazon:webservices
aws_session_duration = 28800
aws_profile          = <new account name>
resource_id          =
subdomain            =
role_arn             = arn:aws:iam::<new account id>:role/SSOAdministratorAccess
region               = us-west-2
```

    The SPid above is specific to the commercial/gov providers in the G Suite console.

  b) Azure AD

``` text
[<new account name>]
app_id               = <Application ID for Amazon Web Service (AWS) from Azure AD's Enterprise Application>
url                  = https://account.activedirectory.windowsazure.com/
username             = <you>@example.com
provider             = AzureAD
mfa                  = Auto
skip_verify          = false
timeout              = 0
aws_urn              = urn:amazon:webservices
aws_session_duration = 28800
aws_profile          = <new account name>
resource_id          =
subdomain            =
role_arn             = arn:aws:iam::<new account id>:role/SSOAdministratorAccess
region               = us-west-2
```

    You can now use **`saml2aws login -a <new account name>`** to log into the new account with your personal user credentials.
    From now on, you can use **`aws --profile <new account name> ...`**
    instead of the assumed role that was created earlier

7. Recover the root password for the new account

    1.  Go to <https://console.aws.amazon.com/console/home>

    2.  Enter the email address you used to create the account above

    3.  Click "Forgot password"

    4.  An email will be sent to the email address to allow password reset

8. Store new root credentials in your password manager
