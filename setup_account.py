#!/usr/bin/env python
import argparse
import boto3
import logging

from boto3.session import Session
from infra_buckets.infra_buckets import InfraBuckets
from new_sub_account.new_sub_account import AccountCreator
from pathlib import Path
from setup_sso.setup_sso import AccountSetup
from time import sleep
from typing import Optional, List
from vpc_cleaner.vpc_cleaner import AccountCleaner

_LOG_LEVEL_STRINGS = {
    'CRITICAL': logging.CRITICAL,
    'ERROR': logging.ERROR,
    'WARNING': logging.WARNING,
    'INFO': logging.INFO,
    'DEBUG': logging.DEBUG
}


def main(
        account_name: str,
        ivy_tag: str,
        saml_provider: str,
        saml_file: str,
        phase: str,
        purpose: str,
        log_level: str = "INFO",
        email: Optional[str] = None,
        regions: Optional[List[str]] = None
) -> None:
    # Setup logging facility
    logging.basicConfig(format="%(asctime)s %(levelname)s (%(threadName)s) [%(name)s] %(message)s")
    log = logging.getLogger()  # Gets the root logger
    log.setLevel(_LOG_LEVEL_STRINGS[log_level])

    if email:
        log.info("I will try to create sub-account %s", account_name)
        sleep_time: int = 50
        # Create sub account
        account = AccountCreator()
        account.create(email, account_name)
        sub_account_role_arn = f"arn:aws:iam::{account.account_id}:role/OrganizationAccountAccessRole"
        log.info(f"Waiting {sleep_time} seconds after account was created before assuming sub account role, creating alias and removing default VPCs")
        sleep(sleep_time)
        assume_role = boto3.client('sts').assume_role(
            RoleArn=sub_account_role_arn,
            RoleSessionName='IvyAccountTools'
        )
        sub_account_session = Session(
            aws_access_key_id=assume_role['Credentials']['AccessKeyId'],
            aws_secret_access_key=assume_role['Credentials']['SecretAccessKey'],
            aws_session_token=assume_role['Credentials']['SessionToken']
        )
    else:
        log.info("No E-Mail was provided so I will not create a sub-account")
        sub_account_session = None

    # Setup AWS alias and roles
    saml_name = ivy_tag + '-' + saml_provider
    saml_path = Path(saml_file)
    setup_sso = AccountSetup(
        alias_name=account_name,
        saml_provider_name=saml_name,
        saml_provider_file=saml_path,
        session=sub_account_session
    )
    setup_sso.alias()
    setup_sso.saml()
    setup_sso.create_default_roles()

    # Clean vpcs in all regions
    cleaner = AccountCleaner(dry_run=False, session=sub_account_session)
    cleaner.clean_all_vpcs_in_all_regions()

    # Create infra buckets
    infra_buckets = InfraBuckets(
        phase=phase,
        purpose=purpose,
        ivy_tag=ivy_tag,
        regions=regions,
        session=sub_account_session
    )
    infra_buckets.create_buckets()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="""
        1. Creates new sub-account, if email is provided
        2. Removes default VPCs
        3. Sets account alias
        4. Configures SAML
        5. Creates default roles and allows access via SAML only
        """
    )
    parser.add_argument(
        "-a", "--account-name",
        type=str,
        required=True,
        help="AWS Account Name and alias"
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
        "-c", "--phase",
        type=str,
        required=True,
        help="AWS Sub Account Phase (prod, dev, stage, ...)"
    )
    parser.add_argument(
        "-p", "--purpose",
        type=str,
        required=True,
        help="AWS Sub Account purpose (app, tools, sandbox, ...)"
    )
    parser.add_argument(
        "-r", "--regions",
        type=str,
        help="Comma-separated list of AWS regions"
    )
    parser.add_argument(
        "-e", "--e-mail",
        type=str,
        default=None,
        dest="email",
        help="E-Mail address for the AWS Sub Account"
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
    regions = None
    if args.regions:
        regions = [
            region
            for region in args.regions.split(",")
        ]

    main(
        account_name=args.account_name,
        ivy_tag=args.ivy_tag,
        saml_provider=args.saml_provider,
        saml_file=args.saml_file,
        log_level=args.log_level,
        email=args.email,
        phase=args.phase,
        purpose=args.purpose,
        regions=regions
    )
