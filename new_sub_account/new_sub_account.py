#!/usr/bin/env python
import argparse
import boto3
import json
import logging
import sys
import botocore.client

from botocore import session as se
from botocore.exceptions import BotoCoreError
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
    account_id = None

    def __init__(self, client: Optional[OrganizationsClient] = None) -> None:
        if client is None:
            self.client = boto3.client('organizations')
        else:
            self.client = client

    def create(self, email: str, name: str) -> None:
        if self.account_id is None:
            aws_partition = boto3.client('ec2').meta.partition
            if aws_partition == '':
                self.account_id = self._government(email, name)
            else:
                self.account_id = self._commercial(email, name)
        else:
            self.log.info("Account has been created and its ID is %s", self.account_id)

    def _commercial(self, email: str, name: str) -> str:
        """ Create Commercial Account """
        self.log.debug("I will try to create commercial account with name %s", name)
        response = self.client.create_account(
            Email=email,
            AccountName=name
        )['CreateAccountStatus']
        return self._get_status(response)['AccountId']

    def _goverment(self, email: str, name: str) -> str:
        """ Create Government Account """
        response = self.client.create_gov_cloud_account(
            Email=email,
            AccountName=name
        )['CreateAccountStatus']
        return self._get_status(response)['GovCloudAccountId']

    def _get_status(self, response: dict) -> dict:
        """ Get Account Creation Status """
        self.log.info(
            "New account status is %s, Account ID is %s, if request failed the error is %s",
            response['State'],
            response.get('AccountId', 'not yet assigned'),
            response.get('FailureReason', 'No Failures')
        )
        counter: int = 1
        account_status = self.client.describe_create_account_status(
            CreateAccountRequestId=response['Id']
        )['CreateAccountStatus']
        while account_status['State'] == 'IN_PROGRESS' or counter >= 5:
            self.log.info(
                "Account ID %s is still in the process of being creating waiting for %s seconds",
                account_status['AccountId'],
                counter
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

def main(
        email: str,
        sub_account_name: str,
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
        "-e", "--e-mail",
        type=str,
        dest="email",
        required=True,
        help="E-Mail address for the AWS Sub Account"
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
        args.log_level
    )
