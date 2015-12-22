from setuptools import setup

setup(
    name='aws-mfa',
    version='0.0.2',
    description='Manage AWS MFA Credentials',
    author='Brian Nuszkowski',
    scripts=['aws-mfa'],
    install_requires=['boto3>=1.2.3']
)
