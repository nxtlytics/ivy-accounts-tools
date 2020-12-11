#!/usr/bin/env python
import boto3
import logging
import os

from pathlib import Path

from new_sub_account.new_sub_account import AccountCreator
from setup_sso.setup_sso import AccountSetup
from vpc_cleaner.vpc_cleaner import AccountCleaner
from infra_buckets.infra_buckets import infra_buckets_parser, InfraBuckets

# Setup logging facility
logging.basicConfig(format="%(asctime)s %(levelname)s (%(threadName)s) [%(name)s] %(message)s")
log = logging.getLogger()  # Gets the root logger
log.setLevel(logging.INFO)

os.environ['AWS_ACCESS_KEY_ID'] = 'local'
os.environ['AWS_SECRET_ACCESS_KEY'] = 'stack'
os.environ['AWS_DEFAULT_REGION'] = 'us-west-2'
endpoint_url = 'http://localhost:4566'
account_name = 'ivy-test-sub-account'
ivy_tag = 'ivy'
saml_provider = 'gsuite'
saml_doc = './tests/test_saml.xml'
email = 'infeng+' + account_name + 'example.com'
phase = 'test'
purpose = 'sandbox'
s3_regions = ['us-east-1', 'us-east-2']
aws_partition = boto3.client('ec2', endpoint_url=endpoint_url).meta.partition
orgs_client = boto3.client('organizations', endpoint_url=endpoint_url)
iam_client = boto3.client('iam', endpoint_url=endpoint_url)
s3_client = boto3.client('s3', endpoint_url=endpoint_url)
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
    all_regions = [element['RegionName'] for element in ec2_client.describe_regions()['Regions']]
    vpc_list_before = []
    for region in all_regions:
        vpcs = [element['VpcId'] for element in
                boto3.client('ec2', region_name=region, endpoint_url=endpoint_url).describe_vpcs(
                    Filters=[
                        {
                            'Name': 'isDefault',
                            'Values': [
                                'true',
                            ],
                        },
                    ]
                )['Vpcs']]
        vpc_list_before.extend(vpcs)
    assert len(vpc_list_before) == 24
    cleaner = AccountCleaner(dry_run=False, endpoint_url=endpoint_url)
    cleaner.clean_all_vpcs_in_all_regions()
    vpc_list_after = []
    for region in all_regions:
        vpcs = [element['VpcId'] for element in
                boto3.client('ec2', region_name=region, endpoint_url=endpoint_url).describe_vpcs(
                    Filters=[
                        {
                            'Name': 'isDefault',
                            'Values': [
                                'true',
                            ],
                        },
                    ]
                )['Vpcs']]
        vpc_list_after.extend(vpcs)
    assert len(vpc_list_after) == 0


def test_infra_buckets_argparser() -> None:
    arguments = [
        '-c', phase,
        '-p', purpose,
        '-t', ivy_tag
    ]
    parsed_args = infra_buckets_parser(arguments)
    assert parsed_args.phase == phase
    assert parsed_args.purpose == purpose
    assert parsed_args.ivy_tag == ivy_tag
    assert parsed_args.regions is None
    assert parsed_args.log_level == 'INFO'


def test_infra_buckets_argparser_with_regions() -> None:
    arguments = [
        '-c', phase,
        '-p', purpose,
        '-t', ivy_tag,
        '-r', ','.join(s3_regions)
    ]
    parsed_args = infra_buckets_parser(arguments)
    assert parsed_args.phase == phase
    assert parsed_args.purpose == purpose
    assert parsed_args.ivy_tag == ivy_tag
    assert parsed_args.regions == s3_regions
    assert parsed_args.log_level == 'INFO'


def test_infra_buckets_creator_on_default_region() -> None:
    # Create s3 infra bucket on default region and account name
    buckets_before = [
        bucket["Name"]
        for bucket in s3_client.list_buckets().get("Buckets", [])
    ]
    tags = {
        f"{ivy_tag}:sysenv": f"{ivy_tag}-aws-{os.environ['AWS_DEFAULT_REGION']}-{purpose}-{phase}",
        f"{ivy_tag}:service": "s3",
        f"{ivy_tag}:role": "bucket",
        f"{ivy_tag}:group": "main",
        f"{ivy_tag}:createdby": "ivy-account-tools",
        f"{ivy_tag}:purpose": purpose,
        f"{ivy_tag}:phase": phase
    }
    infra_buckets = InfraBuckets(
        phase=phase,
        purpose=purpose,
        ivy_tag=ivy_tag,
        endpoint_url=endpoint_url
    )
    created_buckets = infra_buckets.create_buckets()
    created_tags = {
        tag['Key']: tag['Value']
        for tag in s3_client.get_bucket_tagging(
            Bucket=created_buckets[0]
        )['TagSet']
    }
    assert len(buckets_before) == 0
    assert len(created_buckets) == 1
    assert created_buckets[0] not in buckets_before
    assert all(s3_client.get_public_access_block(
                Bucket=created_buckets[0]
            )["PublicAccessBlockConfiguration"].values())
    assert created_tags == tags


def test_infra_buckets_creator_duplicate() -> None:
    # Try to create duplicate s3 infra bucketon default region and account name
    buckets_before = [
        bucket["Name"]
        for bucket in s3_client.list_buckets().get("Buckets", [])
    ]
    infra_buckets = InfraBuckets(
        phase=phase,
        purpose=purpose,
        ivy_tag=ivy_tag,
        endpoint_url=endpoint_url
    )
    created_buckets = infra_buckets.create_buckets()
    assert len(buckets_before) == 1
    assert len(created_buckets) == 1
    assert created_buckets[0] in buckets_before


def test_infra_buckets_creator_on_regions() -> None:
    # Create s3 infra buckets based on list of regions and account name
    buckets_before = [
        bucket["Name"]
        for bucket in s3_client.list_buckets().get("Buckets", [])
    ]
    infra_buckets = InfraBuckets(
        phase=phase,
        purpose=purpose,
        ivy_tag=ivy_tag,
        regions=s3_regions,
        endpoint_url=endpoint_url
    )
    created_buckets = infra_buckets.create_buckets()
    buckets_after = [
        bucket["Name"]
        for bucket in s3_client.list_buckets().get("Buckets", [])
    ]
    assert len(buckets_before) == 1
    assert len(buckets_after) == 3
    assert created_buckets[0] not in buckets_before
    assert created_buckets[1] not in buckets_before
    assert created_buckets[0] in buckets_after
    assert created_buckets[1] in buckets_after