#!/usr/bin/env python
import boto3
import json
import logging

from pathlib import Path

from new_sub_account.new_sub_account import new_sub_account_parser, AccountCreator
from setup_sso.setup_sso import setup_sso_parser, AccountSetup
from vpc_cleaner.vpc_cleaner import AccountCleaner
from infra_buckets.infra_buckets import infra_buckets_parser, InfraBuckets
from thunder_github_automation.thunder_github_automation import ThunderGithubOIDC

# Setup logging facility
logging.basicConfig(format="%(asctime)s %(levelname)s (%(threadName)s) [%(name)s] %(message)s")
log = logging.getLogger()  # Gets the root logger
log.setLevel(logging.INFO)

endpoint_url = "http://localhost:4566"
account_name = "ivy-test-sub-account"
ivy_tag = "ivy"
saml_provider = "gsuite"
saml_doc = "./tests/test_saml.xml"
email = "infeng+" + account_name + "@example.com"
saml_name = ivy_tag + "-" + saml_provider
saml_file = Path(saml_doc)
phase = "test"
purpose = "sandbox"
commercial_region = "us-west-2"
s3_regions = ["us-east-1", "us-east-2"]
commercial_session = boto3.session.Session(
    region_name=commercial_region, aws_access_key_id="local", aws_secret_access_key="stack"
)
commercial_ec2_client = commercial_session.client("ec2", endpoint_url=endpoint_url)
commercial_iam_client = commercial_session.client("iam", endpoint_url=endpoint_url)
commercial_s3_client = commercial_session.client("s3", endpoint_url=endpoint_url)
# create an organization so accounts can be created under it
commercial_orgs_client = commercial_session.client("organizations", endpoint_url=endpoint_url)
commercial_orgs_client.create_organization(FeatureSet="ALL")


def test_sub_account_parser() -> None:
    arguments = ["-a", account_name, "-e", email]
    parsed_args = new_sub_account_parser(arguments)
    assert parsed_args.sub_account_name == account_name
    assert parsed_args.email == email
    assert parsed_args.log_level == "INFO"


def test_sub_account_creation() -> None:
    # Create sub account
    account = AccountCreator(session=commercial_session, endpoint_url=endpoint_url)
    account.create(email, account_name)
    assert type(account.account_id) is str


def test_sub_account_duplicate() -> None:
    """
    Create sub account with same name and email as previous test
    No new account should be created AccountCreator should find
    existing account
    """
    account = AccountCreator(session=commercial_session, endpoint_url=endpoint_url)
    account.create(email, account_name)
    accounts = commercial_orgs_client.list_accounts()["Accounts"]
    assert type(account.account_id) is str
    # should be 2 because we create an organization above which creates a master account
    assert len(accounts) == 2


def test_account_setup_parser() -> None:
    arguments = ["-a", account_name, "-f", saml_doc, "-s", saml_provider, "-t", ivy_tag]
    parsed_args = setup_sso_parser(arguments)
    assert parsed_args.sub_account_name == account_name
    assert parsed_args.saml_file == saml_doc
    assert parsed_args.saml_provider == saml_provider
    assert parsed_args.ivy_tag == ivy_tag
    assert parsed_args.log_level == "INFO"


def test_account_setup() -> None:
    # Setup AWS alias and roles
    setup_sso = AccountSetup(
        alias_name=account_name,
        saml_provider_name=saml_name,
        saml_provider_file=saml_file,
        session=commercial_session,
        endpoint_url=endpoint_url,
    )
    setup_sso.alias()
    setup_sso.saml()
    setup_sso.create_default_roles()
    aliases = [alias for alias in commercial_iam_client.list_account_aliases()["AccountAliases"]]
    saml_providers = [provider["Arn"] for provider in commercial_iam_client.list_saml_providers()["SAMLProviderList"]]
    roles = [role for role in commercial_iam_client.list_roles()["Roles"]]
    roles_arn = [role["Arn"] for role in roles]
    # The changes below are specific to localstack
    # AWS saves AssumeRolePolicyDocument as a dictionary
    # localstack saves AssumeRolePolicyDocument as a string
    roles_aud = [
        json.loads(role["AssumeRolePolicyDocument"])["Statement"][0]["Condition"]["StringEquals"]["SAML:aud"]
        for role in roles
        if role["RoleName"] == "SSOAdministratorAccess"
    ]
    assert account_name in aliases
    assert "arn:aws:iam::000000000000:saml-provider/ivy-gsuite" in saml_providers
    assert "arn:aws:iam::000000000000:role/SSOAdministratorAccess" in roles_arn
    assert "arn:aws:iam::000000000000:role/SSOViewOnlyAccess" in roles_arn
    assert setup_sso.saml_audiences["aws"] == roles_aud[0]


def test_account_setup_duplicate() -> None:
    """
    Try to setup an alias with the same name
    it should fine the previous one and not create it
    aliases should be equal to 1
    """
    setup_sso = AccountSetup(
        alias_name=account_name,
        saml_provider_name=saml_name,
        saml_provider_file=saml_file,
        session=commercial_session,
        endpoint_url=endpoint_url,
    )
    setup_sso.alias()
    setup_sso.saml()
    setup_sso.create_default_roles()
    aliases = [alias for alias in commercial_iam_client.list_account_aliases()["AccountAliases"]]
    saml_providers = [provider["Arn"] for provider in commercial_iam_client.list_saml_providers()["SAMLProviderList"]]
    roles = [role["Arn"] for role in commercial_iam_client.list_roles()["Roles"]]
    assert len(aliases) == 1
    assert len(saml_providers) == 1
    assert len(roles) == 3


def test_github_oidc_setup() -> None:
    """
    Try to setup GitHub OIDC provider in AWS, and creates a role to allow
    Thunder's Github Action to manage the SysEnv.
    """
    repo = "thunder"
    org = "some-org"
    setup_gh_oidc = ThunderGithubOIDC(
        repository=repo, organization=org, session=commercial_session, endpoint_url=endpoint_url
    )
    setup_gh_oidc.setup_github_oidc()
    oidc_providers = [
        provider["Arn"]
        for provider in commercial_iam_client.list_open_id_connect_providers()["OpenIDConnectProviderList"]
    ]
    roles = [role for role in commercial_iam_client.list_roles()["Roles"]]
    roles_arn = [role["Arn"] for role in roles]
    # The changes below are specific to localstack
    # AWS saves AssumeRolePolicyDocument as a dictionary
    # localstack saves AssumeRolePolicyDocument as a string
    roles_aud = [
        json.loads(role["AssumeRolePolicyDocument"])["Statement"][0]["Condition"]["StringEquals"][
            "token.actions.githubusercontent.com:aud"
        ]
        for role in roles
        if role["RoleName"] == "ThunderGithubAutomation"
    ]
    roles_repo = [
        json.loads(role["AssumeRolePolicyDocument"])["Statement"][0]["Condition"]["StringLike"][
            "token.actions.githubusercontent.com:sub"
        ]
        for role in roles
        if role["RoleName"] == "ThunderGithubAutomation"
    ]
    assert "arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com" in oidc_providers
    assert "arn:aws:iam::000000000000:role/ThunderGithubAutomation" in roles_arn
    assert setup_gh_oidc._github_provider["audience"] == roles_aud[0]
    assert f"repo:{org}/{repo}" == roles_repo[0]


def test_github_oidc_setup_duplicate() -> None:
    """
    Try to setup duplicate GitHub OIDC provider in AWS. It should NOT create a new one.
    """
    repo = "thunder"
    org = "some-org"
    setup_gh_oidc = ThunderGithubOIDC(
        repository=repo, organization=org, session=commercial_session, endpoint_url=endpoint_url
    )
    setup_gh_oidc.setup_github_oidc()
    oidc_providers = [
        provider["Arn"]
        for provider in commercial_iam_client.list_open_id_connect_providers()["OpenIDConnectProviderList"]
    ]
    roles = [role for role in commercial_iam_client.list_roles()["Roles"]]
    assert len(oidc_providers) == 1
    assert len(roles) == 4


def test_vpc_cleaner() -> None:
    # Clean vpcs in all regions
    all_regions = [element["RegionName"] for element in commercial_ec2_client.describe_regions()["Regions"]]
    vpc_list_before = []
    for region in all_regions:
        vpcs = [
            element["VpcId"]
            for element in commercial_session.client(
                "ec2", region_name=region, endpoint_url=endpoint_url
            ).describe_vpcs(
                Filters=[
                    {
                        "Name": "isDefault",
                        "Values": [
                            "true",
                        ],
                    },
                ]
            )[
                "Vpcs"
            ]
        ]
        vpc_list_before.extend(vpcs)
    assert len(vpc_list_before) == 24
    cleaner = AccountCleaner(dry_run=False, session=commercial_session, endpoint_url=endpoint_url)
    cleaner.clean_all_vpcs_in_all_regions()
    vpc_list_after = []
    for region in all_regions:
        vpcs = [
            element["VpcId"]
            for element in commercial_session.client(
                "ec2", region_name=region, endpoint_url=endpoint_url
            ).describe_vpcs(
                Filters=[
                    {
                        "Name": "isDefault",
                        "Values": [
                            "true",
                        ],
                    },
                ]
            )[
                "Vpcs"
            ]
        ]
        vpc_list_after.extend(vpcs)
    assert len(vpc_list_after) == 0


def test_infra_buckets_argparser() -> None:
    arguments = ["-c", phase, "-p", purpose, "-t", ivy_tag]
    parsed_args = infra_buckets_parser(arguments)
    assert parsed_args.phase == phase
    assert parsed_args.purpose == purpose
    assert parsed_args.ivy_tag == ivy_tag
    assert parsed_args.regions is None
    assert parsed_args.log_level == "INFO"


def test_infra_buckets_argparser_with_regions() -> None:
    arguments = ["-c", phase, "-p", purpose, "-t", ivy_tag, "-r", ",".join(s3_regions)]
    parsed_args = infra_buckets_parser(arguments)
    assert parsed_args.phase == phase
    assert parsed_args.purpose == purpose
    assert parsed_args.ivy_tag == ivy_tag
    assert parsed_args.regions == s3_regions
    assert parsed_args.log_level == "INFO"


def test_infra_buckets_creator_on_default_region() -> None:
    # Create s3 infra bucket on default region and account name
    buckets_before = [bucket["Name"] for bucket in commercial_s3_client.list_buckets().get("Buckets", [])]
    tags = {
        f"{ivy_tag}:sysenv": f"{ivy_tag}-aws-{commercial_region}-{purpose}-{phase}",
        f"{ivy_tag}:service": "s3",
        f"{ivy_tag}:role": "bucket",
        f"{ivy_tag}:group": "main",
        f"{ivy_tag}:createdby": "ivy-account-tools",
        f"{ivy_tag}:purpose": purpose,
        f"{ivy_tag}:phase": phase,
    }
    infra_buckets = InfraBuckets(
        phase=phase, purpose=purpose, ivy_tag=ivy_tag, session=commercial_session, endpoint_url=endpoint_url
    )
    created_buckets = infra_buckets.create_buckets()
    created_tags = {
        tag["Key"]: tag["Value"] for tag in commercial_s3_client.get_bucket_tagging(Bucket=created_buckets[0])["TagSet"]
    }
    buckets_after = [bucket["Name"] for bucket in commercial_s3_client.list_buckets().get("Buckets", [])]
    assert len(buckets_before) == 0
    assert len(created_buckets) == 1
    assert created_buckets[0] not in buckets_before
    assert all(
        commercial_s3_client.get_public_access_block(Bucket=created_buckets[0])[
            "PublicAccessBlockConfiguration"
        ].values()
    )
    assert created_tags == tags
    assert created_buckets[0] in buckets_after


def test_infra_buckets_creator_duplicate() -> None:
    # Try to create duplicate s3 infra bucket on default region and account name
    buckets_before = [bucket["Name"] for bucket in commercial_s3_client.list_buckets().get("Buckets", [])]
    infra_buckets = InfraBuckets(
        phase=phase, purpose=purpose, ivy_tag=ivy_tag, session=commercial_session, endpoint_url=endpoint_url
    )
    created_buckets = infra_buckets.create_buckets()
    assert len(buckets_before) == 1
    assert len(created_buckets) == 1
    assert created_buckets[0] in buckets_before


def test_infra_buckets_creator_on_regions() -> None:
    # Create s3 infra buckets based on list of regions and account name
    buckets_before = [bucket["Name"] for bucket in commercial_s3_client.list_buckets().get("Buckets", [])]
    infra_buckets = InfraBuckets(
        phase=phase,
        purpose=purpose,
        ivy_tag=ivy_tag,
        regions=s3_regions,
        session=commercial_session,
        endpoint_url=endpoint_url,
    )
    created_buckets = infra_buckets.create_buckets()
    buckets_after = [bucket["Name"] for bucket in commercial_s3_client.list_buckets().get("Buckets", [])]
    assert len(buckets_before) == 1
    assert len(buckets_after) == 3
    assert created_buckets[0] not in buckets_before
    assert created_buckets[1] not in buckets_before
    assert created_buckets[0] in buckets_after
    assert created_buckets[1] in buckets_after
