#!/usr/bin/env python
import argparse
import boto3
import logging
import sys

from pathlib import Path
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
    saml_audiences: dict = {
        'aws': 'https://signin.aws.amazon.com/saml',
        'aws-cn': 'https://signin.amazonaws.cn/saml',
        'aws-us-gov': 'https://signin.amazonaws-us-gov.com/saml'
    }
    start_of_policy = '{"Version":"2012-10-17","Statement":[{"Action":"sts:AssumeRoleWithSAML","Effect":"Allow",' \
                      '"Condition":{"StringEquals":{"SAML:aud":" '
    middle_of_policy = '"}},"Principal":{"Federated":"'
    end_of_policy = '"}}]}'

    def __init__(
            self,
            alias_name: str,
            saml_provider_name: str,
            saml_provider_file: Path,
            session: Optional[boto3.session.Session] = None,
            endpoint_url: Optional[str] = None
    ) -> None:
        self.alias_name = alias_name
        self.saml_provider_name = saml_provider_name
        self.saml_provider_file = saml_provider_file
        if session is None:
            self.session = boto3.session.Session()
        else:
            self.session = session
        self.endpoint_url = endpoint_url
        self.account_id = self.session.client(
            'sts',
            endpoint_url=self.endpoint_url
        ).get_caller_identity().get('Account')
        self.aws_partition = self.session.client(
            'ec2',
            endpoint_url=self.endpoint_url
        ).meta.partition
        self.saml_provider_arn = f"arn:{self.aws_partition}:iam::{self.account_id}:saml-provider/{self.saml_provider_name}"
        self.roles_arn = {
            'SSOAdministratorAccess': f"arn:{self.aws_partition}:iam::{self.account_id}:role/SSOAdministratorAccess",
            'SSOViewOnlyAccess': f"arn:{self.aws_partition}:iam::{self.account_id}:role/SSOViewOnlyAccess"
        }
        self.client = self.session.client('iam', endpoint_url=self.endpoint_url)

    def alias(self) -> None:
        """ Setup Account Alias """
        if self._check_alias(self.alias_name):
            self.log.info("I will try to setup account_alias: %s", self.alias_name)
            try:
                self.client.create_account_alias(
                    AccountAlias=self.alias_name
                )
                self.log.info("Account alias %s was created", self.alias_name)
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

    def saml(self) -> None:
        """ Setup SAML Provider """
        if self._check_saml_provider():
            self.log.info("I will try to setup SAML provider %s", self.saml_provider_name)
            with self.saml_provider_file.open() as f:
                try:
                    saml = self.client.create_saml_provider(
                        SAMLMetadataDocument=f.read(),
                        Name=self.saml_provider_name
                    )
                    self.log.info("SAML provider ARN is %s", saml['SAMLProviderArn'])
                    self.saml_provider_arn = saml['SAMLProviderArn']
                except Exception as e:
                    self.log.exception("SAML provider setup failed with error %s", e)
        else:
            self.log.info("SAML provider has been setup and its ARN is %s", self.saml_provider_arn)

    def _check_saml_provider(self) -> bool:
        """ Check if saml provider has been created """
        saml_providers = [
            provider['Arn']
            for provider in self.client.list_saml_providers()['SAMLProviderList']
        ]
        if self.saml_provider_arn in saml_providers:
            return False
        else:
            return True

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
            self.client.attach_role_policy(
                RoleName=role_name,
                PolicyArn=policy_arn
            )
        except Exception as e:
            self.log.exception("Policy %s failed to attach to role %s with error %s", policy_arn, role_name, e)

    def create_role(self, role_name: str, policy_arn: str, policy_document: str) -> None:
        """ Create Role and attach a Policy to it """
        if self._check_role(role_name=role_name):
            try:
                self.log.info(
                    "I will try to create role with name %s for account ID %s",
                    role_name,
                    self.saml_provider_arn.split(':')[4]
                )
                role = self._create_role(role_name, policy_document)
                self._attach_role_policy(role_name, policy_arn)
                self.roles_arn[role_name] = role['Arn']
                self.log.info("Role was created, its ARN is %s", role['Arn'])
            except Exception as e:
                self.log.exception("Creation of role %s failed with error %s", role_name, e)
        else:
            self.log.info("Role already exists, its ARN is %s", self.roles_arn.get(role_name))

    def _check_role(self, role_name: str) -> bool:
        current_roles = [
            role['Arn']
            for role in self.client.list_roles()['Roles']
        ]
        if self.roles_arn[role_name] in current_roles:
            return False
        else:
            return True

    def create_default_roles(self) -> None:
        """ Create Default Roles """
        try:
            aws_partition = self.saml_provider_arn.split(':')[1]
            policy_document = ''.join([
                self.start_of_policy,
                self.saml_audiences[aws_partition],
                self.middle_of_policy,
                self.saml_provider_arn,
                self.end_of_policy
            ])
            admin_role_name = 'SSOAdministratorAccess'
            admin_policy_arn = f"arn:{aws_partition}:iam::aws:policy/AdministratorAccess"
            self.create_role(
                role_name=admin_role_name,
                policy_arn=admin_policy_arn,
                policy_document=policy_document
            )
            read_role_name = 'SSOViewOnlyAccess'
            read_policy_arn = f"arn:{aws_partition}:iam::aws:policy/job-function/ViewOnlyAccess"
            self.create_role(
                role_name=read_role_name,
                policy_arn=read_policy_arn,
                policy_document=policy_document
            )
        except Exception as e:
            self.log.exception("Creation of default roles failed with error %s", e)



def setup_sso_parser(arguments) -> argparse.Namespace:
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
    return parser.parse_args(arguments)

if __name__ == "__main__":
    args = setup_sso_parser(sys.argv[1:])
    logging.basicConfig(format="%(asctime)s %(levelname)s (%(threadName)s) [%(name)s] %(message)s")
    log = logging.getLogger()  # Gets the root logger
    log.setLevel(_LOG_LEVEL_STRINGS[args.log_level])
    saml_name = args.ivy_tag + '-' + args.saml_provider
    saml_path = Path(args.saml_file)
    setup_sso = AccountSetup(
        alias_name=args.sub_account_name,
        saml_provider_name=saml_name,
        saml_provider_file=saml_path
    )
    setup_sso.alias()
    setup_sso.saml()
    setup_sso.create_default_roles()
