#!/usr/bin/env python
# Copyright (C) 2017 stryngs.

from setuptools import setup

setup(
    name = 'wifiEssentials',
    version = '1.0.4',
    author = 'stryngs',
    author_email = 'info@ethicalreporting.org',
    packages = ['wifiEssentials', 'wifiEssentials.lib'],
    include_package_data = True,
    url = 'https://github.com/ICSec/wifiEssentials',
    license ='GNU General Public License v2',
    keywords = '802.11 wifi essentials',
    description='Essential nuances for Python Scapy revolving around 802.11'
)
