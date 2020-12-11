#!/usr/bin/env python
import argparse
import boto3
import logging
import re
import sys
import urllib.parse

from typing import Optional, List

_LOG_LEVEL_STRINGS = {
    'CRITICAL': logging.CRITICAL,
    'ERROR': logging.ERROR,
    'WARNING': logging.WARNING,
    'INFO': logging.INFO,
    'DEBUG': logging.DEBUG
}


class InfraBuckets:
    log = logging.getLogger(__name__)
    infrastructure_suffix = "-infra"

    def __init__(
            self,
            phase: str,
            purpose: str,
            ivy_tag: str,
            regions: Optional[List[str]] = None,
            session: Optional[boto3.session.Session] = None,
            endpoint_url: Optional[str] = None
    ) -> None:
        if session is None:
            self.session = boto3.session.Session()
        else:
            self.session = session
        if regions is None:
            self.regions = [self.session.region_name]
        else:
            self.regions = regions
        self.endpoint_url = endpoint_url
        self.phase = phase
        self.purpose = purpose
        self.ivy_tag = ivy_tag
        self.client = self.session.client(
            "s3",
            endpoint_url=self.endpoint_url
        )

    def create_buckets(
            self
    ) -> List[str]:
        buckets = [
            f"{self.ivy_tag}-aws-{region}-{self.purpose}-{self.phase}{self.infrastructure_suffix}"
            for region in self.regions
        ]
        self.log.info("Buckets to create are: %s", buckets)
        existing_buckets = [
            bucket["Name"]
            for bucket in self.client.list_buckets().get("Buckets", [])
        ]
        self.log.info("Existing buckets are: %s", existing_buckets)
        [
            self._create_bucket(
                bucket_name=bucket,
                region=bucket.split("-")[2]
            )
            for bucket in buckets if bucket not in existing_buckets
        ]
        [
            self._set_bucket_public_access_block(
                bucket_name=bucket
            )
            for bucket in buckets
        ]
        [
            self._set_bucket_tags(
                bucket_name=bucket,
                tags={
                    f"{self.ivy_tag}:sysenv": f"{re.sub(self.infrastructure_suffix, '', bucket)}",
                    f"{self.ivy_tag}:service": "s3",
                    f"{self.ivy_tag}:role": "bucket",
                    f"{self.ivy_tag}:group": "main",
                    f"{self.ivy_tag}:createdby": "ivy-account-tools",
                    f"{self.ivy_tag}:purpose": self.purpose,
                    f"{self.ivy_tag}:phase": self.phase
                }
            )
            for bucket in buckets
        ]
        return buckets

    def _create_bucket(
            self,
            bucket_name: str,
            region: str
    ) -> None:
        if self.endpoint_url:
            regional_endpoint_url = self.endpoint_url
        else:
            meta_endpoint = self.session.client(
                "s3",
                region_name=region,
                endpoint_url=self.endpoint_url
            ).meta.endpoint_url
            regional_endpoint_url = urllib.parse.urlparse(meta_endpoint).hostname
        try:
            self.session.client(
                "s3",
                region_name=region,
                endpoint_url=regional_endpoint_url
            ).create_bucket(
                ACL='private',
                Bucket=bucket_name,
                CreateBucketConfiguration={} if region == 'us-east-1' else {'LocationConstraint': region}
            )
            self.log.info("Bucket %s creation succeeded", bucket_name)
        except Exception as e:
            self.log.error("Bucket %s creation failed with error: %s", bucket_name, e)

    def _set_bucket_public_access_block(
            self,
            bucket_name: str
    ) -> None:
        try:
            self.client.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            self.log.info("Bucket %s public access block policy was set", bucket_name)
        except Exception as e:
            self.log.error("Bucket %s public access block policy failed to be set with error: %s", bucket_name, e)

    def _set_bucket_tags(
            self,
            bucket_name: str,
            tags: dict
    ) -> None:
        try:
            self.client.put_bucket_tagging(
                Bucket=bucket_name,
                Tagging={
                    'TagSet': [
                        {
                            'Key': k,
                            'Value': v
                        }
                        for k, v in tags.items()
                    ]
                }
            )
            self.log.info("Setting tags for bucket %s succeeded", bucket_name)
        except Exception as e:
            self.log.error("Setting tags for bucket %s failed with error: %s", bucket_name, e)


def infra_buckets_parser(arguments) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Creates infrastructure s3 buckets per sysenv"
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
        "-t", "--ivy-tag",
        type=str,
        default="ivy",
        help="Ivy tag also known as namespace"
    )
    parser.add_argument(
        "-r", "--regions",
        type=str,
        help="Comma-separated list of AWS regions"
    )
    parser.add_argument(
        "-l", "--log-level",
        type=str,
        default="INFO",
        choices=_LOG_LEVEL_STRINGS.keys(),
        help="Set the logging output level"
    )
    parsed_args = parser.parse_args(args=arguments)
    regions = None
    if parsed_args.regions:
        regions = [
            region
            for region in parsed_args.regions.split(",")
        ]
    parsed_args.regions = regions
    return parsed_args


if __name__ == "__main__":
    args = infra_buckets_parser(sys.argv[1:])
    logging.basicConfig(format="%(asctime)s %(levelname)s (%(threadName)s) [%(name)s] %(message)s")
    log = logging.getLogger()  # Gets the root logger
    log.setLevel(_LOG_LEVEL_STRINGS[args.log_level])
    infra_buckets = InfraBuckets(
        phase=args.phase,
        purpose=args.purpose,
        ivy_tag=args.ivy_tag,
        regions=args.regions
    )
    infra_buckets.create_buckets()
