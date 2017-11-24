#!/usr/bin/env python
# Copyright (C) 2017 stryngs.

from setuptools import setup

setup(
    name = 'scapyEssentials',
    version = '1.0.0',
    author = 'stryngs',
    author_email = 'info@ethicalreporting.org',
    packages = ['scapyEssentials', 'scapyEssentials.lib'],
    include_package_data = True,
    url = 'https://github.com/ICSec/scapyEssentials',
    license ='GNU General Public License v2',
    keywords = '802.11 scapy essentials',
    description='Essential nuances for Python Scapy'
)
