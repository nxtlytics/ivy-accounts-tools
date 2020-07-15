#!/usr/bin/env python
from __future__ import print_function

import sys
import json
from botocore import session as se
import boto3
from botocore.exceptions import BotoCoreError
import logging
import click


class VPCCleaner:
    log = logging.getLogger(__name__)

    vpc_id = None

    session = None
    vpc_resource = None
    ec2 = None
    region = None

    dry_run = False

    def __init__(self, vpc_id, region=None, dry_run=False):
        self.vpc_id = vpc_id
        # inherit session from caller, if not specified use default
        # (to allowing passing region without explicitly passing)
        self.region = region
        self.session = boto3.Session(region_name=region)
        self.ec2 = self.session.resource('ec2')
        self.vpc_resource = self.ec2.Vpc(vpc_id)
        self.dry_run = dry_run

    def del_igw(self):
        """ Detach and delete the internet-gateway """
        igws = self.vpc_resource.internet_gateways.all()
        if igws:
            for igw in igws:
                try:
                    self.log.info("Detaching and Removing IGW igw-id: [%s]", igw.id)
                    igw.detach_from_vpc(
                        DryRun=self.dry_run,
                        VpcId=self.vpc_id
                    )
                    igw.delete(
                        DryRun=self.dry_run
                    )
                except Exception as e:
                    self.log.exception("Detaching/removing IGW failed with error [%s]", e)

    def del_sub(self):
        """ Delete the subnets """
        subnets = self.vpc_resource.subnets.all()
        default_subnets = [self.ec2.Subnet(subnet.id) for subnet in subnets if subnet.default_for_az]

        if default_subnets:
            try:
                for sub in default_subnets:
                    self.log.info("Removing subnet sub-id: [%s]", sub.id)
                    sub.delete(
                        DryRun=self.dry_run
                    )
            except Exception as e:
                self.log.exception("Deleting subnet failed with error [%s]", e)

    def del_rtb(self):
        """ Delete the route-tables """
        rtbs = self.vpc_resource.route_tables.all()
        if rtbs:
            try:
                for rtb in rtbs:
                    assoc_attr = [rtb.associations_attribute for rtb in rtbs]
                    if [rtb_ass[0]['RouteTableId'] for rtb_ass in assoc_attr if rtb_ass[0]['Main'] == True]:
                        self.log.warning("Deleting route table: " + rtb.id + " is the main route table, continue...")
                        continue
                    self.log.info("Removing rtb-id: [%s]", rtb.id)
                    table = self.ec2.RouteTable(rtb.id)
                    table.delete(
                        DryRun=self.dry_run
                    )
            except Exception as e:
                self.log.exception("Deleting route table failed with error [%s]", e)

    def del_acl(self):
        """ Delete the network-access-lists """
        acls = self.vpc_resource.network_acls.all()

        if acls:
            try:
                for acl in acls:
                    if acl.is_default:
                        self.log.warning("Deleting NACL: " + acl.id + " is the default NACL, continue...")
                        continue
                    self.log.info("Removing acl-id: [%s]", acl.id)
                    acl.delete(
                        DryRun=self.dry_run
                    )
            except Exception as e:
                self.log.exception("Deleting NACL failed with error [%s]", e)

    def del_sgp(self):
        """ Delete any security-groups """
        sgps = self.vpc_resource.security_groups.all()
        if sgps:
            try:
                for sg in sgps:
                    if sg.group_name == 'default':
                        self.log.warning("Deleting security group: " +sg.id + " is the default security group, continue...")
                        continue
                    self.log.info("Removing sg-id: [%s]", sg.id)
                    sg.delete(
                        DryRun=self.dry_run
                    )
            except Exception as e:
                self.log.exception("Deleting security group failed with error [%s]", e)

    def del_vpc(self):
        """ Delete the VPC """
        try:
            self.log.info("Removing vpc-id: [%s]", self.vpc_resource.id)
            self.vpc_resource.delete(
                DryRun=self.dry_run
            )
        except Exception as e:
            self.log.exception(e)
            #self.log.error("Please remove dependencies and delete VPC manually.")

    def clean_all(self):
        steps = [
            self.del_igw,
            self.del_sub,
            self.del_rtb,
            self.del_acl,
            self.del_sgp,
            self.del_vpc
        ]

        for step in steps:
            try:
                self.log.info("Running step [%s] for VPC [%s] in region [%s]", step.__name__, self.vpc_id, self.region)
                step()
                self.log.debug("Finished step [%s] for VPC [%s] in region [%s]", step.__name__, self.vpc_id, self.region)
            except Exception as e:
                self.log.exception("Unhandled exception in step [%s]. %s", step.__name__, e)

    # def dosomethinghere(self):
    #     """
    #     Do the work - order of operation
    #
    #     1.) Delete the internet-gateway
    #     2.) Delete subnets
    #     3.) Delete route-tables
    #     4.) Delete network access-lists
    #     5.) Delete security-groups
    #     6.) Delete the VPC
    #     """
    #
    #     master_client = boto3.client('ec2')
    #     regions = self.get_regions(master_client)
    #
    #     for region in regions:
    #         try:
    #             self.client = boto3.client('ec2', region_name=region)
    #             self.ec2 = boto3.resource('ec2', region_name=region)
    #         except BotoCoreError as e:
    #             self.log.exception("Failure to gain connection to AWS", e)
    #
    #         vpcs = self.get_default_vpcs()
    #         for vpc in vpcs:
    #             print("\n" + "\n" + "REGION:" + region + "\n" + "VPC Id:" + vpc)
    #             self.del_igw(vpc)
    #             self.del_sub(vpc)
    #             self.del_rtb(vpc)
    #             self.del_acl(vpc)
    #             self.del_sgp(vpc)
    #             self.del_vpc(vpc)


class AccountCleaner:
    log = logging.getLogger(__name__)

    session = None
    dry_run = False

    def __init__(self, dry_run=False):
        self.dry_run = dry_run
        self.session = boto3.Session()

    def _get_regions(self):
        """ Build a region list """
        reg_list = []
        regions = self.session.client('ec2').describe_regions()
        data_str = json.dumps(regions)
        resp = json.loads(data_str)
        region_str = json.dumps(resp['Regions'])
        region = json.loads(region_str)
        for reg in region:
            reg_list.append(reg['RegionName'])
        return reg_list

    def _get_default_vpcs(self, region):
        vpc_list = []
        vpcs = self.session.client('ec2', region_name=region).describe_vpcs(
            Filters=[
                {
                    'Name' : 'isDefault',
                    'Values' : [
                        'true',
                    ],
                },
            ]
        )
        vpcs_str = json.dumps(vpcs)
        resp = json.loads(vpcs_str)
        data = json.dumps(resp['Vpcs'])
        vpcs = json.loads(data)

        for vpc in vpcs:
            vpc_list.append(vpc['VpcId'])

        return vpc_list

    def clean_vpc_in_region(self, vpc_id, region):
        self.log.info("Cleaning VPC [%s] in region [%s]", vpc_id, region)

        vpc_cleaner = VPCCleaner(vpc_id=vpc_id, region=region, dry_run=self.dry_run)
        vpc_cleaner.clean_all()

    def clean_all_vpcs_in_region(self, region):
        self.log.info("Cleaning AWS region [%s] of all VPCs...", region)
        for vpc_id in self._get_default_vpcs(region):
            self.clean_vpc_in_region(vpc_id, region)

    def clean_all_vpcs_in_all_regions(self):
        regions = self._get_regions()
        for region in regions:
            self.clean_all_vpcs_in_region(region)


@click.command()
@click.option('--really-delete', is_flag=True, default=False, help="Really delete VPC resources (scary!)")
def app(really_delete):
    logging.basicConfig(format="%(asctime)s %(levelname)s (%(threadName)s) [%(name)s] %(message)s")
    log = logging.getLogger()  # Gets the root logger
    log.setLevel(logging.INFO)

    # If really delete is true, dry run is false
    dry_run = not really_delete

    log.info("Cleaning all VPCs in all regions! Dry run: [%s]", dry_run)

    cleaner = AccountCleaner(dry_run=dry_run)
    cleaner.clean_all_vpcs_in_all_regions()


if __name__ == "__main__":
    app()

