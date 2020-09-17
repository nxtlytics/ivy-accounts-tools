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
    account_id = None
    aws_partition = None

    def __init__(self, client: Optional[OrganizationsClient] = None, aws_partition: Optional[str] = None) -> None:
        if client is None:
            self.client = boto3.client('organizations')
        else:
            self.client = client
        if aws_partition is None:
            self.aws_partition = boto3.client('ec2').meta.partition
        else:
            self.aws_partition = aws_partition

    def create(self, email: str, name: str) -> None:
        """ Creates Account based on partition """
        if self._check_account(email,name):
            if self.aws_partition == 'aws-us-gov':
                self.account_id = self._government(email, name)
            else:
                self.account_id = self._commercial(email, name)
        else:
            self.log.info("No sub account will be created")

    def _check_account(self, email: str, name: str) -> bool:
        """ Check if an account with email or name already exists """
        paginator = self.client.get_paginator("list_accounts")
        page_iterator = paginator.paginate()
        for element in page_iterator:
            for account in element['Accounts']:
                if name in account.values() or email in account.values():
                    self.log.info("An account with name %s and/or email %s already exists, its account ID is %s", name, email, account['Id'])
                    self.account_id = account['Id']
                    return False
        else:
            self.log.info("Did not find an account with name %s nor email %s", name, email)
            return True

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
        while account_status['State'] == 'IN_PROGRESS':
            if counter >= 5:
                break
            self.log.info(
                "Account ID %s is still in the process of being creating waiting for %s seconds",
                account_status.get('AccountId', 'not yet assigned'),
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
    account.create(email, sub_account_name)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Creates new AWS sub-account"
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
