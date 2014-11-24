#!/usr/bin/env python
from ConfigParser import ConfigParser
from argparse import ArgumentParser
from boto.ec2 import connect_to_region
from boto.exception import EC2ResponseError
from sys import stderr


def _stderr(level, message):
    print >> stderr, "%s: %s" % (level, str(message))


def _info(message):
    _stderr("INFO", message)


def _warn(message):
    _stderr("WARN", message)


def _rule_to_str(rule, grant):
    return ','.join([rule.ip_protocol, rule.from_port, rule.to_port,
                     str(grant)])


def _handle_ec2responseerror(e, rule, grant):
    if e.errors[0][0] == 'InvalidGroup.NotFound':
        _warn("Failed to create a rule because '%s' does not exist in "
              "destination." % grant)
    elif e.errors[0][0] == 'InvalidPermission.Duplicate':
        pass
    elif e.errors[0][0] == 'DryRunOperation':
        _info("%s - %s" % (_rule_to_str(rule, grant), e.errors[0][1]))
    else:
        raise e


def _get_conn(region, creds_file=None):
    kwargs = {}
    if creds_file is not None:
        config = ConfigParser()
        config.read(creds_file)
        for key in ['aws_access_key_id', 'aws_secret_access_key']:
            kwargs[key] = config.get('Credentials', key)

    return connect_to_region(region, **kwargs)


class sync_security_group():
    dry_run = True

    def _parse_args(self):
        parser = ArgumentParser(description='Sync security groups between '
                                            'regions or accounts.')

        parser.add_argument('-n', '--name',
                            required=True,
                            help='the group name')
        parser.add_argument('-s', '--source',
                            default='us-east-1',
                            help='the source region')
        parser.add_argument('--source-vpc',
                            help='the source vpc id')
        parser.add_argument('-d', '--destination',
                            required=True,
                            help='the destination region')
        parser.add_argument('--dest-vpc',
                            help='the destination vpc id')
        parser.add_argument('-c', '--creds',
                            help='the source boto credentials file')
        parser.add_argument('--dest-creds',
                            help='the destination boto credentials file '
                                 '(defaults to source)')
        parser.add_argument('--for-keeps',
                            action='store_true',
                            help='disable dry-run mode; do it for real')
        parser.add_argument('--delete-removed',
                            action='store_true',
                            help='delete extra (removed) rules in destination')
        parser.add_argument('--pretty-sure-about-us-east-1',
                            action='store_true',
                            help='override the us-east-1 safety lock')

        args = parser.parse_args()
        self.dry_run = not args.for_keeps
        return args

    def _get_sg(self, conn, name, description=None, vpc_id=None, create=False):
        sg = None
        try:
            sgs = []
            if vpc_id is None:
                sgs = conn.get_all_security_groups(name)
            else:
                sgs = [sg for sg in conn.get_all_security_groups(name)
                       if sg.vpc_id == vpc_id]

            if len(sgs) != 1:
                raise RuntimeError("Didn't find one-and-only-one destination "
                                   "security group (found %s)." % len(sgs))
            sg = sgs[0]
        except EC2ResponseError as e:
            if e.code == 'InvalidGroup.NotFound' and create:
                _warn("Security group '%s' not found in destination, creating "
                      "it." % name)
                try:
                    sg = conn.create_security_group(name,
                                                    description,
                                                    vpc_id,
                                                    dry_run=self.dry_run)
                except EC2ResponseError as e:
                    if e.code == 'DryRunOperation':
                        _info("create_security_group - %s" % e.errors[0][1])
            else:
                raise e
        return sg

    def run(self):
        args = self._parse_args()

        if args.destination == 'us-east-1' and not args.pretty_sure_about_us_east_1:
            raise RuntimeError("For the love of god, no. No robots copying to "
                               "us-east-1.")

        # Get left-hand security group
        lconn = _get_conn(args.source, args.creds)
        lsg = self._get_sg(lconn, args.name)

        # Get right-hand security group
        rconn = _get_conn(args.destination, args.dest_creds or args.creds)
        rsg = self._get_sg(rconn, lsg.name, lsg.description,
                           args.dest_vpc, True)

        if rsg is None and self.dry_run:
            _warn("This is a dry run on a group that doesn't exist. No point "
                  "in continuing (nothing to test against).")
            return 0

        # Copy source rules to destination rules
        rules = set()  # This is a stupid little set to store a hashable
                       # version of each rule (for left-not-in-right
                       # comparisons later).
        for lrule in lsg.rules:
            for lgrant in lrule.grants:
                rules.add(_rule_to_str(lrule, lgrant))
                kwargs = {'group_id': rsg.id,
                          'ip_protocol': lrule.ip_protocol,
                          'from_port': lrule.from_port,
                          'to_port': lrule.to_port,
                          'dry_run': self.dry_run}

                rsg_grant_id = None
                if lgrant.name is None:
                    kwargs.update({
                        'cidr_ip': lgrant.cidr_ip,
                    })
                else:
                    rsg_grant_id = self._get_sg(rconn, lgrant.name,
                                                None, rsg.vpc_id).id
                    kwargs.update({
                        'src_security_group_owner_id': rsg.owner_id,
                        'src_security_group_group_id': rsg_grant_id
                    })

                try:
                    rconn.authorize_security_group(**kwargs)
                except EC2ResponseError as e:
                    _handle_ec2responseerror(e, lrule, lgrant)

        # Check for extra destination rules
        for rrule in rsg.rules:
            for rgrant in rrule.grants:
                if rgrant.cidr_ip is None and rgrant.group_id is None:
                    continue
                rstr_rule = _rule_to_str(rrule, rgrant)
                if rstr_rule not in rules:
                    if args.delete_removed:
                        try:
                            rsg.revoke(rrule.ip_protocol, rrule.from_port,
                                       rrule.to_port, rgrant.cidr_ip,
                                       rgrant.group_id, dry_run=self.dry_run)
                        except EC2ResponseError as e:
                            _handle_ec2responseerror(e, rrule, rgrant)
                    else:
                        _warn("Extra rule '%s' found in destination group."
                              % rstr_rule)

        # Success
        return 0
