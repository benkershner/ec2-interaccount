# ec2-interaccount

## Introduction

This is a collection of Boto-based scripts and libraries that make it easier
to migrate and sync data between multiple EC2 regions and accounts. The
command line scripts that are made available are:

- sync-security-groups

## Installation

You can install the package via PyPI:

	$ sudo pip install ec2_interaccount

If you're installing from the Github repo, simply take advantage of the
Python setup script:

	$ sudo python setup.py install

## Usage

### sync-security-groups

`sync-security-groups` allows you to perform one-way sync between mulitple
VPCs in multiple regions on multiple accounts.

##### Command line options

	-n, --name NAME                the group name
	-s, --source SOURCE            the source region
	--source-vpc SOURCE_VPC        the source vpc id
	-d, --destination DESTINATION  the destination region
	--dest-vpc DEST_VPC            the destination vpc id
	-c, --creds CREDS              the source boto credentials file
	--dest-creds DEST_CREDS        the destination boto credentials file (defaults to source)
	--for-keeps                    disable dry-run mode; do it for real
	--delete-removed               delete extra (removed) rules in destination
	--pretty-sure-about-us-east-1  override the us-east-1 safety lock

