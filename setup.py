# -*- coding: utf-8 -*-
import ast
import re

from setuptools import find_packages, setup

_version_re = re.compile(r'__version__\s+=\s+(.*)')

with open('src/slipstream/libcloud/__init__.py', 'rb') as f:
    version = str(ast.literal_eval(_version_re.search(
        f.read().decode('utf-8')).group(1)))

install_requires = [
    'slipstream-api',
    'libcloud==0.18.0',
]

setup(
    name='slipstream-libcloud-driver',
    version=version,
    author="SixSq Sarl",
    author_email='support@sixsq.com',
    url='http://sixsq.com/slipstream',
    description="A libcloud driver for SlipStream.",
    keywords='slipstream devops libcloud driver',
    package_dir={'': 'src'},
    packages=find_packages('src'),
    namespace_packages=['slipstream'],
    zip_safe=False,
    license='Apache License, Version 2.0',
    include_package_data=True,
    install_requires=install_requires,
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: Apache Software License',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Topic :: Software Development'
    ],
)
