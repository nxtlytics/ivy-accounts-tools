#!/usr/bin/env python
import click
import logging
import boto3
import json
from mypy_boto3_iam.client import IAMClient
from typing import Optional


class ThunderGithubOIDC:
    _github_provider = {
        "provider": "token.actions.githubusercontent.com",
        "audience": "sts.amazonaws.com",
        "thumbprints": [
            # https://github.blog/changelog/2022-01-13-github-actions-update-on-oidc-based-deployments-to-aws/
            "6938fd4d98bab03faadb97b34396831e3780aea1"
        ]
    }

    _DEFAULT_ROLE_NAME = "ThunderGithubAutomation"
    _POLICY_NAME = "ThunderAutomationAccess"

    def __init__(self, repository: str, organization: str, role_name: Optional[str],
                 session: Optional[boto3.session.Session] = None):
        self.log = logging.getLogger(self.__class__.__name__)

        self.repository = repository
        self.organization = organization

        if role_name is None:
            self.role_name = self._DEFAULT_ROLE_NAME
        else:
            self.role_name = role_name

        self.log.info("Setting up AWS oidc provider for Github [%s/%s] with role name [%s]", self.organization,
                      self.repository, self.role_name)

        if session is None:
            self.client: IAMClient = boto3.session.Session().client("iam")
        else:
            self.client: IAMClient = session.client("iam")

    def _check_provider(self) -> Optional[str]:
        # check if the SSO provider exists, return the arn if so
        providers = self.client.list_open_id_connect_providers()['OpenIDConnectProviderList']
        provider_arn = next(
            filter(
                lambda provider: self._github_provider["provider"] in provider['Arn'],
                providers
            ), {}
        ).get('Arn')
        if provider_arn:
            self.log.info("Using existing oidc provider [%s]", provider_arn)
        return provider_arn

    def _create_provider(self) -> str:
        if provider_arn := self._check_provider():
            # if the provider exists, just use it as-is
            return provider_arn

        # create the provider
        try:
            response = self.client.create_open_id_connect_provider(
                Url=f"https://{self._github_provider['provider']}",
                ClientIDList=[
                    self._github_provider["audience"]
                ],
                ThumbprintList=self._github_provider["thumbprints"]
            )
            if provider_arn := response['OpenIDConnectProviderArn']:
                self.log.debug("Created provider [%s]", provider_arn)
                return provider_arn
            else:
                self.log.error("Role ARN not in response from create_open_id_connect_provider: [%s]", response)
                raise Exception("No ARN in response from OIDC provider creation request")
        except Exception as e:
            raise Exception("Unable to create OIDC provider") from e

    def _check_role(self) -> Optional[str]:
        roles = self.client.list_roles()
        role = next(
            filter(
                lambda role: role["RoleName"] == self.role_name,
                roles.get("Roles", [])
            ), {}
        )
        role_name, role_arn = role.get("RoleName"), role.get("Arn")
        if role_arn:
            self.log.info("Using existing role [%s] [%s]", role_name, role_arn)
        return role_name

    def _create_role(self, provider_arn: str):
        if role_name := self._check_role():
            return role_name

        # create the role
        try:
            response = self.client.create_role(
                RoleName=self.role_name,
                AssumeRolePolicyDocument=json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {
                                "Federated": provider_arn,
                            },
                            "Action": "sts:AssumeRoleWithWebIdentity",
                            "Condition": {
                                "StringEquals": {
                                    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
                                },
                                "StringLike": {
                                    "token.actions.githubusercontent.com:sub": f"repo:{self.organization}/{self.repository}"
                                }
                            }
                        }
                    ]
                }),
                Description="Role for Thunder Github Automation",
            )
            role_name, role_arn = response["Role"]["RoleName"], response["Role"]["Arn"]
            if role_arn:
                self.log.info("Created role [%s] [%s]", role_name, role_arn)
                return role_name
            else:
                self.log.error("Role ARN not in response from create_role: [%s]", response)
                raise Exception("No ARN in response from create role request")
        except Exception as e:
            raise Exception("Unable to create role") from e

    def _create_policy(self, role_name: str) -> None:
        # no need to check if the policy exists, we're going to update it anyway
        try:
            self.client.put_role_policy(
                RoleName=role_name,
                PolicyName=self._POLICY_NAME,
                # This policy is the same as the managed AdministratorAccess policy
                # this allows us to scope this down later if required,
                # instead of using a managed policy that cannot be modified.
                PolicyDocument=json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "*",
                            "Resource": "*"
                        }
                    ]
                })
            )
            self.log.info("Successfully put role contents")
        except Exception as e:
            raise Exception("Unable to put policy on role") from e

    def setup_github_oidc(self):
        provider_arn = self._create_provider()
        role_name = self._create_role(provider_arn)
        self._create_policy(role_name)


@click.command()
@click.option('--repo', required=True, help='GitHub repository name to grant AWS access')
@click.option('--org', required=True, help='GitHub organization where the repository exists')
@click.option('--role-name', '-r', help='Optional name of the IAM role to create')
@click.option('-v', '--verbose', count=True)
def cli(repo, org, verbose, role_name):
    """
    This script creates a Github OIDC provider in AWS, and creates a role to allow
    Thunder's Github Action to manage the SysEnv.
    """
    # Set up logging - if -vv enable debug logs from boto, single v gives just debug logs from this script
    logging.basicConfig(format="%(asctime)s %(levelname)s (%(threadName)s) [%(name)s] %(message)s",
                        level=logging.DEBUG if verbose > 1 else logging.INFO)
    if verbose > 0:
        logging.getLogger(ThunderGithubOIDC.__class__.__name__).setLevel(logging.DEBUG)
    ThunderGithubOIDC(repository=repo, organization=org, role_name=role_name).setup_github_oidc()


if __name__ == '__main__':
    cli()
