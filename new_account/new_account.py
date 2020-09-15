#!/usr/bin/env python
import argparse
import boto3
import json
import logging
import sys
import botocore.client

from botocore import session as se
from botocore.exceptions import BotoCoreError
from mypy_boto3_iam.client import IAMClient
from mypy_boto3_organizations.client import OrganizationsClient
from pathlib import Path
from time import sleep
from typing import Optional

_LOG_LEVEL_STRINGS = {
    'CRITICAL': logging.CRITICAL,
    'ERROR': logging.ERROR,
    'WARNING': logging.WARNING,
    'INFO': logging.INFO,
    'DEBUG': logging.DEBUG
}

class AccountCreator:
    log = logging.getLogger(__name__)
    client = None
    commercial_id = None
    goverment_id = None

    def __init__(self, client: Optional[OrganizationsClient] = None) -> None:
        if client is None:
            self.client = boto3.client('organizations')
        else:
            self.client = client

    def commercial(self, email: str, name: str) -> None:
        """ Create Commercial Account """
        if self.commercial_id is None:
            self.log.debug("I will try to create commercial account with name %s", name)
            response = self.client.create_account(
                Email=email,
                AccountName=name
            )['CreateAccountStatus']
            self.commercial_id = self._get_status(response)['AccountId']
        else:
            self.log.info("Commercial account has been created and its ID is %s", self.commercial_id)

    def goverment(self, email: str, name: str) -> dict:
        """ Create Government Account """
        if self.government_id is None:
            response = self.client.create_gov_cloud_account(
                Email=email,
                AccountName=name
            )['CreateAccountStatus']
            self.government_id = self._get_status(response)['GovCloudAccountId']
        else:
            self.log.info("Government account has been created and its ID is %s", self.government_id)


    def _get_status(self, response: dict) -> dict:
        """ Get Account Creation Status """
        self.log.info(
            "New account status is %s, Account ID is %s, if request failed the error is %s",
            response['State'],
            response['AccountId'],
            response['FailureReason']
        )
        counter: int = 1
        account_status = self.client.describe_create_account_status(
            CreateAccountRequestId=response['Id']
        )['CreateAccountStatus']
        while account_status['State'] == 'IN_PROGRESS' or counter >= 5:
            self.log.info(
                "Account ID %s is still in the process of being creating waiting for % seconds"
            )
            sleep(counter)
            counter += 1
            account_status = self.client.describe_create_account_status(
                CreateAccountRequestId=response['Id']
            )['CreateAccountStatus']
        if account_status['State'] == 'SUCCEEDED':
            self.log.info("Account creation succeeded")
            return account_status
        elif account_status['State'] == 'FAILED':
            self.log.exception("Account creation failed")
            raise Exception

class AccountSetup:
    log = logging.getLogger(__name__)
    client = None
    alias_name = None
    saml_provider = None
    admin_role_arn = None
    read_role_arn = None
    start_of_policy = '{"Version":"2012-10-17","Statement":[{"Action":"sts:AssumeRoleWithSAML","Effect":"Allow","Condition":{"StringEquals":{"SAML:aud":"https://signin.aws.amazon.com/saml"}},"Principal":{"Federated":"'
    end_of_policy = '"}}]}'

    def __init__(self, client: Optional[IAMClient] = None) -> None:
        if client is None:
            self.client = boto3.client('iam')
        else:
            self.client = client

    def alias(self, account_alias: str) -> None:
        """ Setup Account Alias """
        if self.alias_name is None:
            self.log.debug("I will try to setup account_alias: %s", account_alias)
            try:
                alias = self.client.create_account_alias(
                    AccountAlias=account_alias
                )
                self.log.debug("Account alias was setup with response %s", alias)
                self.alias_name = account_alias
            except Exception as e:
                self.log.exception("Account alias was not setup with error %s", e)
        else:
            self.log.info("Account alias has already been setup and is %s", self.alias_name)

    def saml(self, name: str, saml_file: Path) -> None:
        """ Setup SAML Provider """
        if self.saml_provider is None:
            self.log.debug("I will try to setup SAML provider %s", name)
            with saml_file.open() as f:
                try:
                    saml = self.client.create_saml_provider(
                        SAMLMetadataDocument=f.read(),
                        Name=name
                    )
                    self.log.debug("SAML provider ARN is %s", saml['SAMLProviderArn'])
                    self.saml_provider = saml['SAMLProviderArn']
                except Exception as e:
                    self.log.exception("SAML provider setup failed with error %s", e)
        else:
            self.log.info("SAML provider has been setup and its ARN is %s", self.saml_provider)

    def _create_role(self, role_name: str, policy_document: str) -> dict:
        """ Create a role and attach a policy to it """
        try:
            role_response = self.client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=f.read(),
                MaxSessionDuration=28800,
            )['Role']
            return role_response
        except Exception as e:
            self.log.exception("Role %s was not created, error was %s", role_name, e)

    def _attach_role_policy(self, role_name: str, policy_arn: str) -> None:
        """ Attach a policy to a role """
        try:
            attach_response = self.client.attach_role_policy(
                RoleName=role_name,
                PolicyArn=policy_arn
            )
        except Exception as e:
            self.log.exception("Policy %s failed to attach to role %s with error %s", policy_arn, role_name, e)

    def create_admin_role(self) -> None:
        """ Create Role with Administrator Access """
        role_name = 'SSOAdministratorAccess'
        try:
            policy_document = self.start_of_policy + self.saml_provider + self.end_of_policy
            aws_partition = self.saml_provider.split(':')[1]
            policy_arn = f"arn:{aws_partition}:iam::aws:policy/AdministratorAccess"
            if self.admin_role_arn is None:
                self.log.debug("I will try to create the admin role for account ID %s", self.saml_provider.split(':')[4])
                admin_role = self._create_role(role_name, policy_document)
                self._attach_role_policy(role_name, policy_arn)
                self.admin_role_arn = admin_role['Arn']
            else:
                self.log.info("Admin role already exists, its ARN is %s", self.admin_role_arn)
        except Exception as e:
            self.log.exception("Creation of Admin role failed with error %s", e)

    def create_read_role(self) -> None:
        """ Create Role with Read-Only Access """
        role_name = 'SSOViewOnlyAccess'
        try:
            policy_document = self.start_of_policy + self.saml_provider + self.end_of_policy
            aws_partition = self.saml_provider.split(':')[1]
            policy_arn = f"arn:{aws_partition}:iam::aws:policy/job-function/ViewOnlyAccess"
            if self.admin_role_arn is None:
                self.log.debug("I will try to create the read-only role for account ID %s", self.saml_provider.split(':')[4])
                read_role = self._create_role(role_name, policy_document)
                self._attach_role_policy(role_name, policy_arn)
                self.read_role_arn = read_role['Arn']
            else:
                self.log.info("Read-Only role already exists, its ARN is %s", self.admin_role_arn)
        except Exception as e:
            self.log.exception("Creation of Read-Only role failed with error %s", e)

def main(
        email: str,
        sub_account_name: str,
        ivy_tag: str,
        saml_provider: str,
        saml_file: str,
        create_gov_account: bool,
        log_level: str = 'INFO'
    ) -> None:
    logging.basicConfig(format="%(asctime)s %(levelname)s (%(threadName)s) [%(name)s] %(message)s")
    log = logging.getLogger()  # Gets the root logger
    log.setLevel(_LOG_LEVEL_STRINGS[log_level])
    account = AccountCreator()
    account.commercial(email, sub_account_name)
    sub_account_role_arn = f"arn:aws:iam::{account.commercial_id}:role/OrganizationAccountAccessRole"
    assume_role = boto3.client('sts').assume_role(
        RoleArn=sub_account_role_arn,
        RoleSessionName='IvyAccountTools'
    )
    sub_account_session = Session(
        aws_access_key_id=assume_role['Credentials']['AccessKeyId'],
        aws_secret_access_key=assume_role['Credentials']['SecretAccessKey'],
        aws_session_token=assume_role['Credentials']['SessionToken']
    )
    sub_account_iam = sub_account_session.client('iam')
    setup_sso = AccountSetup(sub_account_iam)
    setup_sso.alias(sub_account_name)
    saml_name = ivy_tag + '-' + saml_provider
    saml_file = Path(saml_file)
    setup_sso.saml(saml_name, saml_file)
    setup_sso.create_admin_role()
    setup_sso.create_read_role()
    if create_gov_account:
        sub_account_organizations = sub_account_session.client('organizations')
        gov_account = AccountCreator(sub_account_organizations)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Creates new commercial sub-account, and optionally its GovCloud account"
    )
    parser.add_argument(
        "-a", "--sub-account-name",
        type=str,
        required=True,
        help="AWS Sub Account Name"
    )
    parser.add_argument(
        "-f", "--saml-metadata-document-file",
        type=str,
        dest="saml_file",
        help="Path to An XML document generated by an identity provider (IdP) that supports SAML 2.0"
    )
    parser.add_argument(
        "-s", "--saml-provider-name",
        type=str,
        default='gsuite',
        dest="saml_provider",
        help="Name of the saml provider. Examples: gsuite, msft"
    )
    parser.add_argument(
        "-e", "--e-mail",
        type=str,
        dest="email",
        help="E-Mail address for the AWS Sub Account"
    )
    parser.add_argument(
        "-g", "--create-gov-account",
        action='store_true',
        default=False,
        dest="create_gov_account",
        help="Create GovCloud Account"
    )
    parser.add_argument(
        "-t", "--ivy-tag",
        type=str,
        default="ivy",
        help="Ivy tag also known as namespace"
    )
    parser.add_argument(
        "-l", "--log-level",
        type=str,
        default='INFO',
        choices=_LOG_LEVEL_STRINGS.keys(),
        help="Set the logging output level"
    )
    args = parser.parse_args()
    main(
        args.email,
        args.sub_account_name,
        args.ivy_tag,
        args.saml_provider,
        args.saml_file,
        args.create_gov_account,
        args.log_level
    )
