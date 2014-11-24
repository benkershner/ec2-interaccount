#!/usr/bin/env python

from setuptools import setup

requires = []

setup(name='ec2_interaccount',
      version='0.1',
      description='Interaccount EC2 libraries and scripts.',
      url='https://github.com/benkershner/ec2-interaccount',
      author='Ben Kershner',
      author_email='ben.kershner@gmail.com',
      license='MIT',
      packages=['ec2_interaccount'],
      install_requires=requires,
      scripts=['bin/sync-security-group'],
      zip_safe=False)
