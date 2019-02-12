#!/usr/bin/env python3

from setuptools import setup, find_packages

with open('requirements.txt') as f:
    required = f.readlines()

setup(
    name='freeipalib',
    version='0.1',
    author='agmtr',
    description='freeipa json library',
    url='https://github.com/agmtr/freeipalib.git',
    license='MIT',
    install_requires=required,
    packages=find_packages()

)
