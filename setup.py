#!/usr/bin/env python

import setuptools

setuptools.setup(
    name='aws-session-credentials',
    version='0.1.0',
    description='Manage AWS session credentials',
    url='https://github.com/thumbtack/aws-session-credentials',
    author='Thumbtack SRE',
    license='Apache License 2.0',
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Topic :: Utilities",
    ],
    keywords='aws',
    packages=setuptools.find_packages(),
    install_requires=['boto3'],
    python_requires='>=2.6,!=3.0.*,!=3.1.*,!=3.2.*,<4',
    entry_points={
        'console_scripts': [
            'aws-session-credentials=aws_session_credentials.aws_session_credentials:main',
        ],
    },
)
