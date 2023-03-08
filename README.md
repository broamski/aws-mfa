aws-mfa: Easily manage your AWS Security Credentials when using Multi-Factor Authentication (MFA)
=================================================================================================

**aws-mfa** makes it easy to manage your AWS SDK Security Credentials when Multi-Factor Authentication (MFA) is enforced on your AWS account. It automates the process of obtaining temporary credentials from the [AWS Security Token Service](http://docs.aws.amazon.com/STS/latest/APIReference/Welcome.html) and updating your [AWS Credentials](https://blogs.aws.amazon.com/security/post/Tx3D6U6WSFGOK2H/A-New-and-Standardized-Way-to-Manage-Credentials-in-the-AWS-SDKs) file (located at `~/.aws/credentials`). Traditional methods of managing MFA-based credentials requires users to write their own bespoke scripts/wrappers to fetch temporary credentials from STS and often times manually update their AWS credentials file.

The concept behind **aws-mfa** is that there are 2 types of credentials:

* `long-term` - Your typcial AWS access keys, consisting of an `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`

* `short-term` - A temporary set of credentials that are generated by AWS STS using your `long-term` credentials in combination with your MFA device serial number (either a hardware device serial number or virtual device ARN) and one time token code. Your short term credentials are the credentials that are actively utilized by the AWS SDK in use.


If you haven't yet enabled multi-factor authentication for AWS API access, check out the [AWS article](http://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_configure-api-require.html) on doing so.


Installation:
-------------
Option 1
```sh
$ pip install aws-mfa
```

Option 2
```sh
1. Clone this repo
2. $ python setup.py install
```

Credentials File Setup
----------------------

In a typical AWS credentials file (located at `~/.aws/credentials`), credentials are stored in sections, denoted by a pair of brackets: `[]`. The `[default]` section stores your default credentials. You can store multiple sets of credentials using different profile names. If no profile is specified, the `[default]` section is always used.

By default long term credential sections are identified by the convention `[<profile_name>-long-term]` and short term credentials are identified by the typical convention: `[<profile_name>]`. The following illustrates how you would configure you credentials file using **aws-mfa** with your default credentials:

```ini
[default-long-term]
aws_access_key_id = YOUR_LONGTERM_KEY_ID
aws_secret_access_key = YOUR_LONGTERM_ACCESS_KEY
```

After running `aws-mfa`, your credentials file would read:

```ini
[default-long-term]
aws_access_key_id = YOUR_LONGTERM_KEY_ID
aws_secret_access_key = YOUR_LONGTERM_ACCESS_KEY


[default]
aws_access_key_id = <POPULATED_BY_AWS-MFA>
aws_secret_access_key = <POPULATED_BY_AWS-MFA>
aws_security_token = <POPULATED_BY_AWS-MFA>
```

Similarly, if you utilize a credentials profile named **development**, your credentials file would look like:

```ini
[development-long-term]
aws_access_key_id = YOUR_LONGTERM_KEY_ID
aws_secret_access_key = YOUR_LONGTERM_ACCESS_KEY
```


After running `aws-mfa`, your credentials file would read:

```ini
[development-long-term]
aws_access_key_id = YOUR_LONGTERM_KEY_ID
aws_secret_access_key = YOUR_LONGTERM_ACCESS_KEY

[development]
aws_access_key_id = <POPULATED_BY_AWS-MFA>
aws_secret_access_key = <POPULATED_BY_AWS-MFA>
aws_security_token = <POPULATED_BY_AWS-MFA>
```

The default naming convention for the credential section can be overriden by using the `--long-term-suffix` and
`--short-term-suffix` command line arguments. For example, in a multi account scenario you can have one AWS account
that manages the IAM users for your organization and have other AWS accounts for development, staging and production
environments.

After running `aws-mfa` once for each environment with a different value for `--short-term-suffix`, your credentials
file would read:

```ini
[myorganization-long-term]
aws_access_key_id = YOUR_LONGTERM_KEY_ID
aws_secret_access_key = YOUR_LONGTERM_ACCESS_KEY

[myorganization-development]
aws_access_key_id = <POPULATED_BY_AWS-MFA>
aws_secret_access_key = <POPULATED_BY_AWS-MFA>
aws_security_token = <POPULATED_BY_AWS-MFA>

[myorganization-staging]
aws_access_key_id = <POPULATED_BY_AWS-MFA>
aws_secret_access_key = <POPULATED_BY_AWS-MFA>
aws_security_token = <POPULATED_BY_AWS-MFA>

[myorganization-production]
aws_access_key_id = <POPULATED_BY_AWS-MFA>
aws_secret_access_key = <POPULATED_BY_AWS-MFA>
aws_security_token = <POPULATED_BY_AWS-MFA>
```

This allows you to access multiple environments without the need to run `aws-mfa` each time you want to switch
environments.

If you don't like the a long term suffix, you can omit it by passing the value `none` for the `--long-term-suffix`
command line argument. After running ``aws-mfa`` once for each environment with a different value for
`--short-term-suffix`, your credentials file would read:

```ini
[myorganization]
aws_access_key_id = YOUR_LONGTERM_KEY_ID
aws_secret_access_key = YOUR_LONGTERM_ACCESS_KEY

[myorganization-development]
aws_access_key_id = <POPULATED_BY_AWS-MFA>
aws_secret_access_key = <POPULATED_BY_AWS-MFA>
aws_security_token = <POPULATED_BY_AWS-MFA>

[myorganization-staging]
aws_access_key_id = <POPULATED_BY_AWS-MFA>
aws_secret_access_key = <POPULATED_BY_AWS-MFA>
aws_security_token = <POPULATED_BY_AWS-MFA>

[myorganization-production]
aws_access_key_id = <POPULATED_BY_AWS-MFA>
aws_secret_access_key = <POPULATED_BY_AWS-MFA>
aws_security_token = <POPULATED_BY_AWS-MFA>
```

Usage
-----

```
--credentials-filepath '\custom_path\.aws\credentials'
                        Specify AWS Credentials filepath to be used
                        instead of default Credentials file.'.
--device arn:aws:iam::123456788990:mfa/dudeman
                        The MFA Device ARN. This value can also be provided
                        via the environment variable 'MFA_DEVICE' or the
                        ~/.aws/credentials variable 'aws_mfa_device'.
--duration DURATION     The duration, in seconds, that the temporary
                        credentials should remain valid. Minimum value: 900
                        (15 minutes). Maximum: 129600 (36 hours). Defaults to
                        43200 (12 hours), or 3600 (one hour) when using
                        '--assume-role'. This value can also be provided via
                        the environment variable 'MFA_STS_DURATION'.
--profile PROFILE       If using profiles, specify the name here. The default
                        profile name is 'default'. The value can also be
                        provided via the environment variable 'AWS_PROFILE'.
--long-term-suffix LONG_TERM_SUFFIX
                        To identify the long term credential section by
                        [<profile_name>-LONG_TERM_SUFFIX]. Use 'none' to
                        identify the long term credential section by
                        [<profile_name>]. Omit to identify the long term 
                        credential section by [<profile_name>-long-term].
--short-term-suffix SHORT_TERM_SUFFIX
                        To identify the short term credential section by
                        [<profile_name>-SHORT_TERM_SUFFIX]. Omit or use 'none'
                        to identify the short term credential section by
                        [<profile_name>].
--assume-role arn:aws:iam::123456788990:role/RoleName
                        The ARN of the AWS IAM Role you would like to assume,
                        if specified. This value can also be provided via the
                        environment variable 'MFA_ASSUME_ROLE'
--role-session-name ROLE_SESSION_NAME
                        Friendly session name required when using --assume-
                        role. By default, this is your local username.
```

**Argument precedence**: Command line arguments take precedence over environment variables.

Usage Example
-------------

Run **aws-mfa** *before* running any of your scripts that use any AWS SDK.


Using command line arguments:

```sh
$> aws-mfa --duration 1800 --device arn:aws:iam::123456788990:mfa/dudeman
INFO - Using profile: default
INFO - Your credentials have expired, renewing.
Enter AWS MFA code for device [arn:aws:iam::123456788990:mfa/dudeman] (renewing for 1800 seconds):123456
INFO - Success! Your credentials will expire in 1800 seconds at: 2015-12-21 23:07:09+00:00
```

Using environment variables:

```sh
export MFA_DEVICE=arn:aws:iam::123456788990:mfa/dudeman
$> aws-mfa --duration 1800
INFO - Using profile: default
INFO - Your credentials have expired, renewing.
Enter AWS MFA code for device [arn:aws:iam::123456788990:mfa/dudeman] (renewing for 1800 seconds):123456
INFO - Success! Your credentials will expire in 1800 seconds at: 2015-12-21 23:07:09+00:00
```

```sh
export MFA_DEVICE=arn:aws:iam::123456788990:mfa/dudeman
export MFA_STS_DURATION=1800
$> aws-mfa
INFO - Using profile: default
INFO - Your credentials have expired, renewing.
Enter AWS MFA code for device [arn:aws:iam::123456788990:mfa/dudeman] (renewing for 1800 seconds):123456
INFO - Success! Your credentials will expire in 1800 seconds at: 2015-12-21 23:07:09+00:00
```

Output of running **aws-mfa** while credentials are still valid:

```sh
$> aws-mfa
INFO - Using profile: default
INFO - Your credentials are still valid for 1541.791134 seconds they will expire at 2015-12-21 23:07:09
```

Using a profile: (profiles allow you to reference different sets of credentials, perhaps for different users or different regions)

```sh
$> aws-mfa --duration 1800 --device arn:aws:iam::123456788990:mfa/dudeman --profile development
INFO - Using profile: development
Enter AWS MFA code for device [arn:aws:iam::123456788990:mfa/dudeman] (renewing for 1800 seconds):666666
INFO - Success! Your credentials will expire in 1800 seconds at: 2015-12-21 23:09:04+00:00
```

Using a profile that is set via the environment variable `AWS_PROFILE`:

```sh
$> export AWS_PROFILE=development
$> aws-mfa --duration 1800 --device arn:aws:iam::123456788990:mfa/dudeman
INFO - Using profile: development
Enter AWS MFA code for device [arn:aws:iam::123456788990:mfa/dudeman] (renewing for 1800 seconds):666666
INFO - Success! Your credentials will expire in 1800 seconds at: 2015-12-21 23:09:04+00:00
```

Assuming a role:

```sh
$> aws-mfa --duration 1800 --device arn:aws:iam::123456788990:mfa/dudeman --assume-role arn:aws:iam::123456788990:role/some-role --role-session-name some-role-session
INFO - Validating credentials for profile: default  with assumed role arn:aws:iam::123456788990:role/some-role
INFO - Obtaining credentials for a new role or profile.
Enter AWS MFA code for device [arn:aws:iam::123456788990:mfa/dudeman] (renewing for 1800 seconds):123456
INFO - Success! Your credentials will expire in 1800 seconds at: 2016-10-24 18:58:17+00:00
```

Assuming a role: Assume a role specified in your `long-term` configuration

```ini
[default-long-term]
aws_access_key_id = YOUR_LONGTERM_KEY_ID
aws_secret_access_key = YOUR_LONGTERM_ACCESS_KEY
assume_role =  arn:aws:iam::123456788990:role/some-role
```

```sh
$> aws-mfa --duration 1800 --device arn:aws:iam::123456788990:mfa/dudeman --role-session-name some-role-session
```

Assuming a role using a profile:

```sh
$> aws-mfa --duration 1800 --device arn:aws:iam::123456788990:mfa/dudeman --profile development --assume-role arn:aws:iam::123456788990:role/some-role --role-session-name some-role-session
INFO - Validating credentials for profile: development with assumed role arn:aws:iam::123456788990:role/some-role
INFO - Obtaining credentials for a new role or profile.
Enter AWS MFA code for device [arn:aws:iam::123456788990:mfa/dudeman] (renewing for 1800 seconds):123456
INFO - Success! Your credentials will expire in 1800 seconds at: 2016-10-24 18:58:17+00:00
```

Assuming a role in multiple accounts and be able to work with both accounts simultaneously (i.e. production an staging):

```sh
$> aws-mfa —profile myorganization --assume-role arn:aws:iam::222222222222:role/Administrator --short-term-suffix production --long-term-suffix none --role-session-name production
INFO - Validating credentials for profile: myorganization-production with assumed role arn:aws:iam::222222222222:role/Administrator
INFO - Your credentials have expired, renewing.
Enter AWS MFA code for device [arn:aws:iam::111111111111:mfa/me] (renewing for 3600 seconds):123456
INFO - Success! Your credentials will expire in 3600 seconds at: 2017-07-10 07:16:43+00:00

$> aws-mfa —profile myorganization --assume-role arn:aws:iam::333333333333:role/Administrator --short-term-suffix staging --long-term-suffix none --role-session-name staging 
INFO - Validating credentials for profile: myorganization-staging with assumed role arn:aws:iam::333333333333:role/Administrator
INFO - Your credentials have expired, renewing.
Enter AWS MFA code for device [arn:aws:iam::111111111111:mfa/me] (renewing for 3600 seconds):123456
INFO - Success! Your credentials will expire in 3600 seconds at: 2017-07-10 07:16:44+00:00

$> aws s3 list-objects —bucket my-production-bucket —profile myorganization-production

$> aws s3 list-objects —bucket my-staging-bucket —profile myorganization-staging
```