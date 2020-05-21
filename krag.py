from typing import List, Tuple, Optional, NoReturn
from html import parser
import urllib3
import subprocess
import json
import getpass
import argparse


class NotFoundError(Exception):
    pass


class InputLocator(parser.HTMLParser):

    def error(self, message) -> NoReturn:
        raise Exception(message)

    def __init__(self, name: str):
        super(InputLocator, self).__init__()

        self._name = name
        self._value: Optional[str] = None

    def feed(self, data: str) -> None:
        super(InputLocator, self).feed(data=data)

    def handle_starttag(self, tag: str, attrs: List[Tuple[str]]):
        if tag == 'input':
            as_dict = {single_attr[0]: single_attr[1] for single_attr in attrs}
            name = as_dict.get('name', '')

            if name == self._name:
                self._value = as_dict['value']

    def get_value(self) -> str:
        if self._value:
            return self._value
        else:
            raise NotFoundError("Could not find authenticity_token.")


def exchange_email_and_password_for_cookies(email, password, one_login_domain):
    https = urllib3.PoolManager()
    one_login_request = https.request(
        'GET',
        f'https://{one_login_domain}.onelogin.com'
    )

    headers = one_login_request.headers
    set_cookie = headers['Set-Cookie']
    response_document = one_login_request.data.decode('utf-8')
    parser = InputLocator('authenticity_token')
    parser.feed(response_document)
    form = {}
    new_headers = {
        'Cookie': set_cookie,
        'Content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Accept': 'text/javascript, text/html, application/xml, text/xml, */*',
    'Host': f'{one_login_domain}.onelogin.com',
    'Origin': f'https://{one_login_domain}.onelogin.com',
    'Referer': f'https://{one_login_domain}.onelogin.com/login'
    }
    form['email'] = email
    form['password'] = password
    form['_'] = ''
    form['authenticity_token'] = parser.get_value()
    post_response = https.request(
        'POST',
        f'https://{one_login_domain}.onelogin.com/sessions',
        fields=form,
        headers=new_headers
    )

    session_cookies = post_response.headers['Set-Cookie']

    return session_cookies



def exchange_mfa_for_saml_assertion(session_cookies, mfa_code, one_login_domain, app_id):
    https = urllib3.PoolManager()
    headers_for_prompt = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,'
                  'image/webp,image/apng,*/*;q=0.8,'
                  'application/signed-exchange;v=b3;q=0.9',
        'Cookie': session_cookies,
        'Host': f'{one_login_domain}.onelogin.com'
    }

    prompt_response = https.request(
        'GET',
        f'https://{one_login_domain}.onelogin.com/client/otp_prompt/{app_id}',
        headers=headers_for_prompt
    )

    decoded_prompt_response = prompt_response.data.decode('utf-8')
    prompt_form = {
        "otp_token_1": mfa_code,
        "_": ""
    }

    new_parser = InputLocator('authenticity_token')

    new_parser.feed(decoded_prompt_response)
    prompt_form['authenticity_token'] = new_parser.get_value()
    headers_for_post_prompt = {
        'Accept': 'text/javascript, text/html, application/xml, text/xml, */*',
        'Content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Host': f'{one_login_domain}.onelogin.com',
        'Origin': f'https://{one_login_domain}.onelogin.com',
        'Referer': f'https://{one_login_domain}.onelogin.com/client/otp_prompt/{app_id}',
        'Cookie': session_cookies
    }

    post_prompt_response = https.request(
        'POST',
        f'https://{one_login_domain}.onelogin.com/client/otp_prompt/{app_id}',
        fields=prompt_form,
        headers=headers_for_post_prompt
    )

    set_persistent_cookies = post_prompt_response.headers['Set-Cookie']
    headers_for_get_select = {
        'Accept': (
            'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,'
            'image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'
        ),
        'Referer': f'https://{one_login_domain}.onelogin.com/client/otp_prompt/{app_id}',
        'Cookie': set_persistent_cookies
    }

    get_select_response = https.request(
        'GET',
        f'https://{one_login_domain}.onelogin.com/client/apps/select/{app_id}',
        headers=headers_for_get_select
    )

    saml_response_parser = InputLocator(name='SAMLResponse')
    saml_response_parser.feed(get_select_response.data.decode('utf-8'))
    saml_assertion = saml_response_parser.get_value()

    return saml_assertion

def exchange_saml_assertion_for_credentials(
        account_id,
        role_name,
        saml_assertion
):

    role_arn = f'arn:aws:iam::{account_id}:role/{role_name}'
    principal_arn = (
        f'arn:aws:iam::{account_id}:saml-provider/OneLoginCrossAccount'
    )

    assume_role_output = subprocess.check_output(
        [
            'aws',
            'sts',
            'assume-role-with-saml',
            '--role-arn',
            role_arn,
            '--principal-arn',
            principal_arn,
            '--saml-assertion',
            saml_assertion
        ]
    )

    decoded_assume_role_output = assume_role_output.decode('utf-8')
    parsed_assume_role_output = json.loads(decoded_assume_role_output)
    credentials = parsed_assume_role_output['Credentials']

    return credentials


def output_credential_environment_commands(credentials):
    aws_access_key_id = credentials['AccessKeyId']
    aws_secret_access_key = credentials['SecretAccessKey']
    aws_session_token = credentials['SessionToken']
    export_commands = [
        f"export AWS_ACCESS_KEY_ID='{aws_access_key_id}'",
        f"export AWS_SECRET_ACCESS_KEY='{aws_secret_access_key}'",
        f"export AWS_SESSION_TOKEN='{aws_session_token}'"
    ]

    output_message = "\n".join(export_commands)
    print(output_message)


def prompt_user_for_email():
    email = getpass.getpass(prompt='Email:')

    return email


def prompt_user_for_password():
    password = getpass.getpass(prompt='Password:')

    return password


def prompt_user_for_mfa_code():
    mfa_code = getpass.getpass(prompt='MFA Code:')

    return mfa_code


def get_credentials():
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument('ACCOUNT_ID')
    argument_parser.add_argument('ROLE_NAME')
    argument_parser.add_argument('ONE_LOGIN_DOMAIN')
    argument_parser.add_argument('APP_ID')

    parsed_args = argument_parser.parse_args()
    account_id = parsed_args.ACCOUNT_ID
    role_name = parsed_args.ROLE_NAME
    one_login_domain = parsed_args.ONE_LOGIN_DOMAIN
    app_id = parsed_args.APP_ID
    email = prompt_user_for_email()
    password = prompt_user_for_password()
    session_cookies = exchange_email_and_password_for_cookies(
        email=email,
        password=password,
        one_login_domain=one_login_domain
    )

    mfa_code = prompt_user_for_mfa_code()
    saml_assertion = exchange_mfa_for_saml_assertion(
        session_cookies=session_cookies,
        mfa_code=mfa_code,
        one_login_domain=one_login_domain,
        app_id=app_id
    )

    credentials = exchange_saml_assertion_for_credentials(
        account_id=account_id,
        role_name=role_name,
        saml_assertion=saml_assertion
    )

    output_credential_environment_commands(credentials=credentials)


if __name__ == '__main__':
    get_credentials()