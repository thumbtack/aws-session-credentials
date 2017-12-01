aws-session-credentials
=======================

.. image:: https://travis-ci.org/thumbtack/aws-session-credentials.svg?branch=master
   :target: https://travis-ci.org/thumbtack/aws-session-credentials

.. image:: https://img.shields.io/pypi/v/aws-session-credentials.svg
   :target: https://pypi.python.org/pypi/aws-session-credentials

.. image:: https://img.shields.io/pypi/l/aws-session-credentials.svg

This python package provides a method for mfa-authenticated API access
to AWS resources.

This tool is just one part of a larger setup that forces programmatic
requests to the AWS API to be authenticated with multi-factor
authentication. For details on how to configure IAM to forbid
non-mfa-authenticated access to AWS resources, consult `this AWS
guide`_.

CLI Tool Setup
--------------

To install the ``aws-session-credentials`` CLI tool, simply install this
package via ``pip``:

::

    pip install git+ssh://git@github.com/thumbtack/aws-session-credentials.git
    aws-session-credentials --help

This package is both Python2 and Python3 compliant and can be safely
used in either environment.

An independent executable is also available on `the GitHub releases
page`_.

For details and examples on invoking the CLI tool, run
``aws-session-credentials --help``.

Development
-----------

This repository is structured as a python package. When working on this
project, it is recommended to install the package in development mode:

::

    git clone git@github.com:thumbtack/aws-session-credentials.git
    pip install -e .

Running tests
~~~~~~~~~~~~~

Tests can be run with:

::

    python -m unittest discover

Release tests are run against both a Python2 and Python3 environment, so
it is recommended to locally test changes using both editions of Python.

Building pex executables
~~~~~~~~~~~~~~~~~~~~~~~~

The ``pex`` project can be used to build an executable file for the CLI
tool:

::

    pip install pex
    pex . -m aws_session_credentials -o aws-session-credentials

.. _this AWS guide: http://docs.aws.amazon.com/IAM/latest/UserGuide/tutorial_users-self-manage-mfa-and-creds.html
.. _the GitHub releases page: https://github.com/thumbtack/aws-session-credentials/releases
