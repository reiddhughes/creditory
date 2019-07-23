import requests
import HTMLParser
import re


class JumpCloud(object):

    def __init__(self, request_factory=requests):
        self._request_factory = request_factory

    def retrieve_aws_saml_assertion(self, username, password, mfa_token):
        headers = {
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept': 'application/json, text/plain, */*',
            'X-Requested-With': 'XMLHttpRequest',
            'Connection': 'keep-alive'
        }

        xsrf_response = self._request_factory.get('https://console.jumpcloud.com/userconsole/xsrf', headers=headers)
        cookies = xsrf_response.cookies
        xsrf_token = xsrf_response.json()['xsrf']

        headers['X-Xsrftoken'] = xsrf_token
        headers['Content-Type'] = 'application/json'

        data = '{"email":"' + username + '","password":"' + password + '"}'

        response = self._request_factory.post('https://console.jumpcloud.com/userconsole/auth', headers=headers, cookies=cookies, data=data)

        mfa_data = '{"otp":"' + mfa_token + '"}'

        mfa_response = self._request_factory.post('https://console.jumpcloud.com/userconsole/auth/mfa', headers=headers, cookies=cookies, data=mfa_data)

        headers.pop('Content-Type')
        self_response = self._request_factory.get('https://console.jumpcloud.com/userconsole/api/self', headers=headers, cookies=cookies)

        # TODO: insert the saml name below
        saml_response = self._request_factory.get('https://sso.jumpcloud.com/saml2/{saml-name}', headers=headers, cookies=cookies)

        search_result = re.search('(?<=name="SAMLResponse" value=").+(?=")', saml_response.text)
        encoded_saml_response = search_result.group(0)
        decoded_saml_resposne = HTMLParser.HTMLParser().unescape(encoded_saml_response)

        return decoded_saml_resposne
