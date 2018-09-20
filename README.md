aws-mfa-spok
=================================================================================================

**aws-mfa-spok** makes it easy to manage your AWS SDK Security Credentials when Multi-Factor Authentication (MFA) is enforced on your AWS account. It automates the process of obtaining temporary credentials from the [AWS Security Token Service](http://docs.aws.amazon.com/STS/latest/APIReference/Welcome.html) and updating your [AWS Credentials](https://blogs.aws.amazon.com/security/post/Tx3D6U6WSFGOK2H/A-New-and-Standardized-Way-to-Manage-Credentials-in-the-AWS-SDKs) file (located at `~/.aws/credentials` or `\Users\User\.aws\credentials`).

The concept behind `aws-mfa-spok` is that there are 2 types of credentials:

* `long-term` - Your typical AWS access keys, consisting of an `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`

* `short-term` - A temporary set of credentials that are generated by AWS STS using your `long-term` credentials in combination with your MFA device serial number (either a hardware device serial number or virtual device ARN) and one time token code. Your short term credentials are the credentials that are actively utilized by the AWS SDK in use.

Installation
-------------

Two different options are available for installing the `aws-mfa-spok` application. You can run the application natively within a local Python environment, or you can run it from a Docker container.

Option 1: Native Python

If you are running MacOS, you'll need to install Python 3, if you don't have it already:

```
$ brew install python3
```

If you are running Windows, you will likely need to install the latest Python 3 release: [Python 3](https://www.python.org/downloads/windows/). Note that when installing Python on your Windows system you should configure the installer to install Python in the default execution path. You can verify that Python is working properly by opening up a shell environment and running the `python` command. Once Python is running properly on your system, execute the following command to install the `aws-mfa-spok` application:

```
$ pip install aws-mfa-spok
```

Option 2: Docker container

We have created a Docker container which includes Python and the `aws-mfa-spok` application. You can pull down the Docker container by running the command:

```
$ docker pull spok/aws-mfa-spok
```

Credentials File Setup
----------------------

In a typical AWS credentials file (located at `~/.aws/credentials` or `\Users\User\.aws\credentials`), credentials are stored in sections, denoted by a pair of brackets: `[]`. The `[default]` section stores your default credentials. You can store multiple sets of credentials using different profile names. If no profile is specified, the `[default]` section is always used.

By default long term credential sections are identified by the convention `[<profile_name>-long-term]` and short term credentials are identified by the convention: `[<profile_name>]`. The following illustrates how you should configure your credentials file using `aws-mfa-spok` with your default credentials:

```ini
[default-long-term]
aws_access_key_id = YOUR_LONGTERM_KEY_ID
aws_secret_access_key = YOUR_LONGTERM_ACCESS_KEY
aws_mfa_device = arn:aws:iam::602079840429:mfa/user.name
```

Notice how the string `-long-term` was appended to the `default` profile name. You are likely already familiar with the `aws_access_key_id` and `aws_secret_access_key` attributes. You will also need to add an `aws_mfa_device` attribute to each of your configuration profiles. The value of this attribute can be found in the IAM dashboard for your AWS account. However, it's easy to figure out without looking at the dashboard because it follows this format:

```arn:aws:iam::ACCOUNT_ID::mfa/user.name```

where ACCOUNT_ID is the ID number of your AWS account and user.name is your AWS login.

* The account ID for the Spok sandbox account is 602079840429.
* The account ID for the Spok dev account is 439462406438.

For example, if your AWS login name is bob.smith your configuration attribute in the `dev` profile would look like:

```
aws_mfa_device = arn:aws:iam::439462406438:mfa/bob.smith
```

The `aws-mfa-spok` application will transform your credentials file after execution and your credentials file will look like this:

```ini
[default-long-term]
aws_access_key_id = YOUR_LONGTERM_KEY_ID
aws_secret_access_key = YOUR_LONGTERM_ACCESS_KEY
aws_mfa_device = arn:aws:iam::602079840429:mfa/user.name

[default]
aws_access_key_id = <POPULATED_BY_AWS-MFA>
aws_secret_access_key = <POPULATED_BY_AWS-MFA>
aws_security_token = <POPULATED_BY_AWS-MFA>
```

Notice that the `aws-mfa-spok` application converted your `default-long-term` credential into a short-term credential located in the `default` section. Similarly, if you utilize a credentials profile named `dev`, your credentials file would look like:

```ini
[dev-long-term]
aws_access_key_id = YOUR_LONGTERM_KEY_ID
aws_secret_access_key = YOUR_LONGTERM_ACCESS_KEY
```


After running the `aws-mfa-spok` application, your credentials file would read:

```ini
[dev-long-term]
aws_access_key_id = YOUR_LONGTERM_KEY_ID
aws_secret_access_key = YOUR_LONGTERM_ACCESS_KEY

[dev]
aws_access_key_id = <POPULATED_BY_AWS-MFA>
aws_secret_access_key = <POPULATED_BY_AWS-MFA>
aws_security_token = <POPULATED_BY_AWS-MFA>
```

Usage
-----

You can use the `aws-mfa-spok` application to manage your AWS credentials once the application is installed (natively or via Docker container) and once the crendential file is setup with the long-term credentials. 

There are two ways to invoke the `aws-mfa-spok` application depending on how it is installed.

Option 1: Native Python

MacOS users can simply run the `aws-mfa-spok` application without any arguments because the script assumes that the AWS credentials are located in `~/.aws/credentials`. For example:

```
$ aws-mfa-spok
```

The script will ask the user to type in their current MFA token, and once the token is provided it will update the credentials file.

Windows users need to provide the `aws-mfa-spok` application with an argument specifying the location of the credentials file:

```
$ aws-mfa-spok --creds-file C:\Users\User\.aws\credentials
```

The application will modify the appropriate credentials based on the current AWS profile you are using. Typically the profile is specified in an environment variable called `AWS_PROFILE`. For example, if you want to use the `dev` profile you would setup the environment variable like:

```
$ export AWS_PROFILE=dev
```

You can also specify the profile when running the `aws-mfa-spok` command by passing in the `--profile` argument:

```
$ aws-mfa-spok --profile dev
```


Option 2: Docker container

Running the `aws-mfa-spok` application as a Docker container is really easy. You just need to bind mount your local AWS credentials file into a volume on the container and specify the profile you want to update. Here's an example:

```
$ docker run -it --mount type=bind,source=/Users/user.name/.aws/credentials,target=/root/.aws/credentials -e AWS_PROFILE=sandbox spok/aws-mfa-spok
```

Note how this command is also specifying the AWS credential profile that the `aws-mfa-spok` should use by setting an environment variable. It's also bind mounting a credentials file located in `/Users/user.name/.aws/credentials`, which is a Windows credential location.

AWS session tokens generated by the `aws-mfa-spok` application will last around 12 hours. Simply run the application again to generate a new token after the existing token expires.

Building
--------

Here are the steps to build a Docker container:

```
$ docker build -t aws-mfa-spok:latest .
$ docker image tag aws-mfa-spok:latest spok/aws-mfa-spok:latest
$docker push spok/aws-mfa-spok:latest
```
