#!/usr/bin/env python
import argparse
import boto3
import logging
import sys

from time import sleep
from typing import Optional

LOG_LEVEL_STRINGS = {
    "CRITICAL": logging.CRITICAL,
    "ERROR": logging.ERROR,
    "WARNING": logging.WARNING,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
}


class AccountCreator:
    log = logging.getLogger(__name__)
    session = None
    account_id = None
    endpoint_url = None

    def __init__(self, session: Optional[boto3.session.Session] = None, endpoint_url: Optional[str] = None) -> None:
        if session is None:
            self.session = boto3.session.Session()
        else:
            self.session = session
        self.client = self.session.client("organizations", endpoint_url=endpoint_url)

    def create(self, email: str, name: str) -> None:
        """Creates Account if it does not exist"""
        if self._check_account(email, name):
            self.account_id = self._create_account(email, name)
        else:
            self.log.info("No sub account will be created")

    def _check_account(self, email: str, name: str) -> bool:
        """Check if an account with email or name already exists"""
        paginator = self.client.get_paginator("list_accounts")
        page_iterator = paginator.paginate()
        for element in page_iterator:
            for acc in element.get("Accounts", []):
                if name in acc.values() or email in acc.values():
                    self.log.info(
                        "An account with name %s and/or email %s already exists, its account ID is %s",
                        name,
                        email,
                        acc["Id"],
                    )
                    self.account_id = acc["Id"]
                    return False
        else:
            self.log.info("Did not find an account with name %s nor email %s", name, email)
            return True

    def _create_account(self, email: str, name: str) -> str:
        """Create Sub Account"""
        self.log.debug("I will try to create commercial account with name %s", name)
        account_status = self.client.create_account(Email=email, AccountName=name)["CreateAccountStatus"]
        return self._get_status(account_status)["AccountId"]

    def _get_status(self, account_status: dict) -> dict:
        """Get Account Creation Status"""
        self.log.info(
            "New account status is %s, Account ID is %s, if request failed the error is %s",
            account_status["State"],
            account_status.get("AccountId", "not yet assigned"),
            account_status.get("FailureReason", "No Failures"),
        )
        if account_status["State"] == "SUCCEEDED":
            self.log.info("Account creation succeeded")
            return account_status
        elif account_status["State"] == "IN_PROGRESS":
            counter: int = 1
            account_status = self.client.describe_create_account_status(CreateAccountRequestId=account_status["Id"])[
                "CreateAccountStatus"
            ]
            while account_status["State"] == "IN_PROGRESS":
                if counter >= 5:
                    break
                self.log.info(
                    "Account ID %s is still in the process of being creating waiting for %s seconds",
                    account_status.get("AccountId", "not yet assigned"),
                    counter,
                )
                sleep(counter)
                counter += 1
                account_status = self.client.describe_create_account_status(
                    CreateAccountRequestId=account_status["Id"]
                )["CreateAccountStatus"]
            return account_status
        elif account_status["State"] == "FAILED":
            self.log.exception("Account creation failed")
            raise Exception


def new_sub_account_parser(arguments) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Creates new AWS sub-account")
    parser.add_argument("-a", "--sub-account-name", type=str, required=True, help="AWS Sub Account Name")
    parser.add_argument(
        "-e", "--e-mail", type=str, dest="email", required=True, help="E-Mail address for the AWS Sub Account"
    )
    parser.add_argument(
        "-l",
        "--log-level",
        type=str,
        default="INFO",
        choices=LOG_LEVEL_STRINGS.keys(),
        help="Set the logging output level",
    )
    return parser.parse_args(arguments)


if __name__ == "__main__":
    args = new_sub_account_parser(sys.argv[1:])
    logging.basicConfig(format="%(asctime)s %(levelname)s (%(threadName)s) [%(name)s] %(message)s")
    log = logging.getLogger()  # Gets the root logger
    log.setLevel(LOG_LEVEL_STRINGS[args.log_level])
    account = AccountCreator()
    account.create(email=args.email, name=args.sub_account_name)
