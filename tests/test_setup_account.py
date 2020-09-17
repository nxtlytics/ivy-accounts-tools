#!/usr/bin/env python
import boto3
import pytest

from new_sub_account.new_sub_account import AccountCreator
from setup_sso.setup_sso import AccountSetup
from typing import Optional
from vpc_cleaner.vpc_cleaner import VPCCleaner, AccountCleaner

def test_account_setup():
    account_name = 'ivy-test-sub-account'
    ivy-tag = 'ivy'
    saml_provider = 'gsuite'
    saml_file = './tests/test_saml.xml'
    email = 'infeng+' + account_name + 'example.com'

    aws_partition = boto3.client('ec2', endpoint_url='').meta.partition
    if email:
        log.info("I will try to create sub-account %s", account_name)
        # Create sub account
        account = AccountCreator(aws_partition=aws_partition)
        account.create(email, account_name)
        sub_account_role_arn = f"arn:{aws_partition}:iam::{account.account_id}:role/OrganizationAccountAccessRole"
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
    else:
        log.info("No E-Mail was provided so I will not create a sub-account")
        sub_account_session = None
        sub_account_iam = None

    # Setup AWS alias and roles
    setup_sso = AccountSetup(client=sub_account_iam)
    setup_sso.alias(account_name)
    saml_name = ivy_tag + '-' + saml_provider
    saml_file = Path(saml_file)
    setup_sso.saml(saml_name, saml_file)
    setup_sso.create_default_roles()

    # Clean vpcs in all regions
    cleaner = AccountCleaner(dry_run=False, session=sub_account_session)
    cleaner.clean_all_vpcs_in_all_regions()
