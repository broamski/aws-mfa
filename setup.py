from setuptools import setup

setup(
    name='aws-mfa',
    version='0.0.8',
    description='Manage AWS MFA Security Credentials',
    author='Brian Nuszkowski',
    author_email='nuszkowski@protonmail.com',
    scripts=['aws-mfa'],
    url='https://github.com/broamski/aws-mfa',
    install_requires=['boto3>=1.2.3']
)
