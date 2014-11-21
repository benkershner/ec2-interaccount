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


def _get_creds(filename):
    config = ConfigParser()
    config.read(filename)
    kwargs = {}
    for key in ['aws_access_key_id', 'aws_secret_access_key']:
        kwargs[key] = config.get('Credentials', key)
    return kwargs


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


def _parse_args():
    parser = ArgumentParser(description='Sync security groups between regions '
                                        'or accounts.')

    parser.add_argument('-n', '--name',
                        required=True,
                        help='the group name')
    parser.add_argument('-s', '--source',
                        default='us-east-1',
                        help='the source region')
    parser.add_argument('-d', '--destination',
                        required=True,
                        help='the destination region')
    parser.add_argument('-c', '--creds',
                        help='the source boto credentials file')
    parser.add_argument('--dest-creds',
                        help='the destination boto credentials file (defaults '
                             'to source)')
    parser.add_argument('--for-keeps',
                        action='store_true',
                        help='disable dry-run mode; do it for real')
    parser.add_argument('--delete-removed',
                        action='store_true',
                        help='delete extra (removed) rules in destination')

    return parser.parse_args()


class sync_security_group():
    def run(self):
        args = _parse_args()
        dry_run = not args.for_keeps

        if args.destination == 'us-east-1':
            raise RuntimeError("For the love of god, no. No robots copying to "
                               "us-east-1.")

        lkwargs = {}
        if args.creds is not None:
            lkwargs = _get_creds(args.creds)

        rkwargs = lkwargs
        if args.dest_creds is not None:
            rkwargs = _get_creds(args.dest_creds)

        left_conn = connect_to_region(args.source, **lkwargs)
        right_conn = connect_to_region(args.destination, **rkwargs)

        try:
            left_sg = left_conn.get_all_security_groups(args.name)[0]
        except EC2ResponseError:
            raise RuntimeError("Security group '%s' not found in source."
                               % args.name)

        try:
            right_sg = right_conn.get_all_security_groups(args.name)[0]
        except EC2ResponseError:
            _warn("Security group '%s' not found in destination, creating it."
                  % args.name)
            right_sg = right_conn.create_security_group(left_sg.name,
                                                        left_sg.description)

        # Copy source rules to destination rules
        rules = set()
        for rule in left_sg.rules:
            for grant in rule.grants:
                rules.add(_rule_to_str(rule, grant))
                try:
                    right_sg.authorize(rule.ip_protocol, rule.from_port,
                                       rule.to_port, grant.cidr_ip, grant,
                                       dry_run=dry_run)
                except EC2ResponseError as e:
                    _handle_ec2responseerror(e, rule, grant)

        # Check for extra destination rules
        for rule in right_sg.rules:
            for grant in rule.grants:
                if grant.cidr_ip is None and grant.group_id is None:
                    continue
                rstr_rule = _rule_to_str(rule, grant)
                if rstr_rule not in rules:
                    if args.delete_removed:
                        try:
                            right_sg.revoke(rule.ip_protocol, rule.from_port,
                                            rule.to_port, grant.cidr_ip,
                                            grant.group_id, dry_run=dry_run)
                        except EC2ResponseError as e:
                            _handle_ec2responseerror(e, rule, grant)
                    else:
                        _warn("Extra rule '%s' found in destination group."
                              % rstr_rule)

        # Success
        return 0
