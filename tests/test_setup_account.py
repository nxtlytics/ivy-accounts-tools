#!/usr/bin/env python
import boto3
import logging
import os
import pytest

from pathlib import Path
from typing import Optional

from new_sub_account.new_sub_account import AccountCreator
from setup_sso.setup_sso import AccountSetup
from vpc_cleaner.vpc_cleaner import VPCCleaner, AccountCleaner

# Setup logging facility
logging.basicConfig(format="%(asctime)s %(levelname)s (%(threadName)s) [%(name)s] %(message)s")
log = logging.getLogger()  # Gets the root logger
log.setLevel(logging.INFO)

os.environ['AWS_ACCESS_KEY_ID'] = 'local'
os.environ['AWS_SECRET_ACCESS_KEY'] = 'stack'
endpoint_url = 'http://localhost:4566'
account_name = 'ivy-test-sub-account'
ivy_tag = 'ivy'
saml_provider = 'gsuite'
saml_doc = './tests/test_saml.xml'
email = 'infeng+' + account_name + 'example.com'
aws_partition = boto3.client('ec2', endpoint_url=endpoint_url).meta.partition
orgs_client = boto3.client('organizations', endpoint_url=endpoint_url)
iam_client = boto3.client('iam', endpoint_url=endpoint_url)
# create an organization so accounts can be created under it
orgs_client.create_organization(FeatureSet='ALL')

def test_sub_account_creation() -> None:
    # Create sub account
    account = AccountCreator(client=orgs_client, aws_partition=aws_partition)
    account.create(email, account_name)
    assert type(account.account_id) is str

def test_sub_account_duplicate() -> None:
    """
    Create sub account with same name and email as previous test
    No new account should be created AccountCreator should find
    existing account
    """
    account = AccountCreator(client=orgs_client, aws_partition=aws_partition)
    account.create(email, account_name)
    accounts = orgs_client.list_accounts()['Accounts']
    assert type(account.account_id) is str
    # should be 2 because we create an organization above which creates a master account
    assert len(accounts) == 2

def test_account_setup() -> None:
    # Setup AWS alias and roles
    setup_sso = AccountSetup(client=iam_client)
    setup_sso.alias(account_name)
    saml_name = ivy_tag + '-' + saml_provider
    saml_file = Path(saml_doc)
    setup_sso.saml(saml_name, saml_file)
    setup_sso.create_default_roles()
    assert setup_sso.alias_name == account_name
    assert setup_sso.saml_provider == 'arn:aws:iam::000000000000:saml-provider/ivy-gsuite'
    assert 'SSOAdministratorAccess' in setup_sso.roles_arn.keys()
    assert 'SSOViewOnlyAccess' in setup_sso.roles_arn.keys()

def test_account_alias_duplicate() -> None:
    """
    Try to setup an alias with the same name
    it should fine the previous one and not create it
    aliases should be equal to 1
    """
    setup_sso = AccountSetup(client=iam_client)
    setup_sso.alias(account_name)
    aliases = boto3.client('iam', endpoint_url=endpoint_url).list_account_aliases()['AccountAliases']
    assert len(aliases) == 1


def test_vpc_cleaner() -> None:
    # Clean vpcs in all regions
    ec2_client = boto3.client('ec2', endpoint_url=endpoint_url)
    all_regions = [ element['RegionName'] for element in ec2_client.describe_regions()['Regions'] ]
    vpc_list_before = []
    for region in all_regions:
        vpcs = [ element['VpcId'] for element in boto3.client('ec2', region_name=region, endpoint_url=endpoint_url).describe_vpcs(
            Filters=[
                {
                    'Name' : 'isDefault',
                    'Values' : [
                        'true',
                    ],
                },
            ]
        )['Vpcs'] ]
        vpc_list_before.extend(vpcs)
    assert len(vpc_list_before) == 24
    cleaner = AccountCleaner(dry_run=False, endpoint_url=endpoint_url)
    cleaner.clean_all_vpcs_in_all_regions()
    vpc_list_after = []
    for region in all_regions:
        vpcs = [ element['VpcId'] for element in boto3.client('ec2', region_name=region, endpoint_url=endpoint_url).describe_vpcs(
            Filters=[
                {
                    'Name' : 'isDefault',
                    'Values' : [
                        'true',
                    ],
                },
            ]
        )['Vpcs'] ]
        vpc_list_after.extend(vpcs)
    assert len(vpc_list_after) == 0
