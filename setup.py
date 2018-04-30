from setuptools import setup

from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='aws-mfa',
    version='0.0.12',
    description='Manage AWS MFA Security Credentials',
    long_description=long_description,
    long_description_content_type='text/markdown',
    license='MIT',
    author='Brian Nuszkowski',
    author_email='brian@bnuz.co',
    packages=['awsmfa'],
    scripts=['aws-mfa'],
    entry_points={
        'console_scripts': [
            'aws-mfa=awsmfa:main',
        ],
    },
    url='https://github.com/broamski/aws-mfa',
    install_requires=['boto3']
)
