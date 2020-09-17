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

class AccountSetup:
    log = logging.getLogger(__name__)
    client = None
    alias_name = None
    saml_provider = None
    roles_arn: dict = {}
    start_of_policy = '{"Version":"2012-10-17","Statement":[{"Action":"sts:AssumeRoleWithSAML","Effect":"Allow","Condition":{"StringEquals":{"SAML:aud":"https://signin.aws.amazon.com/saml"}},"Principal":{"Federated":"'
    end_of_policy = '"}}]}'

    def __init__(self, client: Optional[IAMClient] = None) -> None:
        if client is None:
            self.client = boto3.client('iam')
        else:
            self.client = client

    def alias(self, account_alias: str) -> None:
        """ Setup Account Alias """
        if self._check_alias(account_alias):
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

    def _check_alias(self, account_alias: str) -> bool:
        """ Check if an account alias has been set already """
        paginator = self.client.get_paginator("list_account_aliases")
        page_iterator = paginator.paginate()
        for element in page_iterator:
            for aliases in element.get('AccountAliases', []):
                if account_alias in aliases:
                    self.log.info("An account alias %s already exists", account_alias)
                    self.alias_name = account_alias
                    return False
        else:
            self.log.info("Did not find an account alias with name %s", account_alias)
            return True

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
        """ Create an IAM Role """
        try:
            role_response = self.client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=policy_document,
                MaxSessionDuration=28800,
            )['Role']
            return role_response
        except Exception as e:
            self.log.exception("Role %s was not created, error was %s", role_name, e)

    def _attach_role_policy(self, role_name: str, policy_arn: str) -> None:
        """ Attach a policy to am IAM Role """
        try:
            attach_response = self.client.attach_role_policy(
                RoleName=role_name,
                PolicyArn=policy_arn
            )
        except Exception as e:
            self.log.exception("Policy %s failed to attach to role %s with error %s", policy_arn, role_name, e)

    def create_role(self, role_name: str, policy_arn: str, policy_document: Optional[str] = None) -> None:
        """ Create Role and attach a Policy to it """
        if policy_document is None:
            policy_document = self.start_of_policy + self.saml_provider + self.end_of_policy
        if self.roles_arn.get(role_name) is None:
            try:
                self.log.info("I will try to create role with name %s for account ID %s", role_name, self.saml_provider.split(':')[4])
                role = self._create_role(role_name, policy_document)
                self._attach_role_policy(role_name, policy_arn)
                self.roles_arn[role_name] = role['Arn']
            except Exception as e:
                self.log.exception("Creation of role %s failed with error %s", role_name, e)
        else:
            self.log.info("Role already exists, its ARN is %s", self.roles_arn.get(role_name))

    def create_default_roles(self) -> None:
        """ Create Default Roles """
        try:
            aws_partition = self.saml_provider.split(':')[1]
            admin_role_name = 'SSOAdministratorAccess'
            admin_policy_arn = f"arn:{aws_partition}:iam::aws:policy/AdministratorAccess"
            self.create_role(role_name=admin_role_name, policy_arn=admin_policy_arn, policy_document=None)
            read_role_name = 'SSOViewOnlyAccess'
            read_policy_arn = f"arn:{aws_partition}:iam::aws:policy/job-function/ViewOnlyAccess"
            self.create_role(role_name=read_role_name, policy_arn=read_policy_arn, policy_document=None)
        except Exception as e:
            self.log.exception("Creation of default roles failed with error %s", e)

def main(
        sub_account_name: str,
        ivy_tag: str,
        saml_provider: str,
        saml_file: str,
        log_level: str = 'INFO'
    ) -> None:
    logging.basicConfig(format="%(asctime)s %(levelname)s (%(threadName)s) [%(name)s] %(message)s")
    log = logging.getLogger()  # Gets the root logger
    log.setLevel(_LOG_LEVEL_STRINGS[log_level])
    setup_sso = AccountSetup()
    setup_sso.alias(sub_account_name)
    saml_name = ivy_tag + '-' + saml_provider
    saml_path = Path(saml_file)
    setup_sso.saml(saml_name, saml_path)
    setup_sso.create_default_roles()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Sets up an AWS account's alias, SAML provider, Admin role and Read-Only role"
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
        required=True,
        help="Path to An XML document generated by an identity provider (IdP) that supports SAML 2.0"
    )
    parser.add_argument(
        "-s", "--saml-provider-name",
        type=str,
        default="gsuite",
        dest="saml_provider",
        help="Name of the saml provider. Examples: gsuite, msft"
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
        default="INFO",
        choices=_LOG_LEVEL_STRINGS.keys(),
        help="Set the logging output level"
    )
    args = parser.parse_args()
    main(
        args.sub_account_name,
        args.ivy_tag,
        args.saml_provider,
        args.saml_file,
        args.gov_account_name,
        args.log_level
    )
