from setuptools import setup

from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='aws-mfa-spok',
    version='0.0.14',
    description='Manage AWS MFA Security Credentials',
    long_description=long_description,
    long_description_content_type='text/markdown',
    license='MIT',
    author='Jason Baker',
    author_email='jason.baker@spok.com',
    packages=['awsmfa'],
    scripts=['aws-mfa-spok'],
    entry_points={
        'console_scripts': [
            'aws-mfa-spok=awsmfa:main',
        ],
    },
    url='https://github.com/jasondbakerspok/aws-mfa',
    install_requires=['boto3']
)
