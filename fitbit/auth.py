import json
from fitbit.compliance import fitbit_compliance_fix
from requests.auth import HTTPBasicAuth
from requests_oauthlib import OAuth2Session
import requests
import fitbit.exceptions
from typing import Tuple
import os
from dotenv import load_dotenv
load_dotenv()

def get_local_tokens() -> Tuple[str, str] | None:
    try:
        with open('token.json', 'r') as f:
            tokens = json.load(f)
            access_token = tokens['access_token']
            refresh_token = tokens['refresh_token']
            return access_token, refresh_token
    except FileNotFoundError:
        print("token.json not found")
        return None

class FitbitOauth2Client(object):
    API_ENDPOINT = "https://api.fitbit.com"
    AUTHORIZE_ENDPOINT = "https://www.fitbit.com"
    API_VERSION = 1

    request_token_url = f"{API_ENDPOINT}/oauth2/token" 
    authorization_url = f"{AUTHORIZE_ENDPOINT}/oauth2/authorize"
    access_token_url = request_token_url
    refresh_token_url = request_token_url

    def __init__(self, client_id, client_secret, access_token=None,
            refresh_token=None, expires_at=None, refresh_cb=None,
            redirect_uri=None, *args, **kwargs):
        """
        Create a FitbitOauth2Client object. Specify the first 7 parameters if
        you have them to access user data. Specify just the first 2 parameters
        to start the setup for user authorization (as an example see gather_key_oauth2.py)
            - client_id, client_secret are in the app configuration page
            https://dev.fitbit.com/apps
            - access_token, refresh_token are obtained after the user grants permission
        """

        self.client_id, self.client_secret = client_id, client_secret
        token = {}
        if access_token and refresh_token:
            token.update({
                'access_token': access_token,
                'refresh_token': refresh_token
            })
        if expires_at:
            token['expires_at'] = expires_at
        self.session = fitbit_compliance_fix(OAuth2Session(
            client_id,
            auto_refresh_url=self.refresh_token_url,
            token_updater=refresh_cb,
            token=token,
            redirect_uri=redirect_uri,
        ))
        self.timeout = kwargs.get("timeout", None)

    def _request(self, method, url, **kwargs):
        """
        A simple wrapper around requests.
        """
        if self.timeout is not None and 'timeout' not in kwargs:
            kwargs['timeout'] = self.timeout

        try:
            response = self.session.request(method, url, **kwargs)

            # If our current token has no expires_at, or something manages to slip
            # through that check
            if response.status_code == 401:
                d = json.loads(response.content.decode('utf8'))
                if d['errors'][0]['errorType'] == 'expired_token':
                    self.refresh_token()
                    response = self.session.request(method, url, **kwargs)

            return response
        except requests.Timeout as e:
            raise exceptions.Timeout(*e.args)

    def make_request(self, url, data=None, method=None, **kwargs):
        """
        Builds and makes the OAuth2 Request, catches errors

        https://dev.fitbit.com/docs/oauth2/#authorization-errors
        """
        data = data or {}
        method = method or ('POST' if data else 'GET')
        response = self._request(
            method,
            url,
            data=data,
            client_id=self.client_id,
            client_secret=self.client_secret,
            **kwargs
        )

        exceptions.detect_and_raise_error(response)

        return response

    def authorize_token_url(self, scope=None, redirect_uri=None, **kwargs):
        """Step 1: Return the URL the user needs to go to in order to grant us
        authorization to look at their data.  Then redirect the user to that
        URL, open their browser to it, or tell them to copy the URL into their
        browser.
            - scope: pemissions that that are being requested [default ask all]
            - redirect_uri: url to which the response will posted. required here
              unless you specify only one Callback URL on the fitbit app or
              you already passed it to the constructor
            for more info see https://dev.fitbit.com/docs/oauth2/
        """

        self.session.scope = scope or [
            "activity",
            "nutrition",
            "heartrate",
            "location",
            "nutrition",
            "profile",
            "settings",
            "sleep",
            "social",
            "weight",
        ]

        if redirect_uri:
            self.session.redirect_uri = redirect_uri

        return self.session.authorization_url(self.authorization_url, **kwargs)

    def fetch_access_token(self, code, redirect_uri=None):

        """Step 2: Given the code from fitbit from step 1, call
        fitbit again and returns an access token object. Extract the needed
        information from that and save it to use in future API calls.
        the token is internally saved
        """
        if redirect_uri:
            self.session.redirect_uri = redirect_uri
        return self.session.fetch_token(
            self.access_token_url,
            username=self.client_id,
            password=self.client_secret,
            client_secret=self.client_secret,
            code=code)

    def refresh_token(self):
        """Step 3: obtains a new access_token from the the refresh token
        obtained in step 2. Only do the refresh if there is `token_updater(),`
        which saves the token.
        """
        token = {}
        if self.session.token_updater:
            token = self.session.refresh_token(
                self.refresh_token_url,
                auth=HTTPBasicAuth(self.client_id, self.client_secret)
            )
            self.session.token_updater(token)

        return token



if __name__ == "__main__":
    
    access_token, refresh_token = get_local_tokens()
    client_id = os.getenv('FITBIT_CLIENT_ID')
    client_secret = os.getenv('FITBIT_CLIENT_SECRET')
    
    client = FitbitOauth2Client(
        client_id,
        client_secret,
        access_token=access_token,
        refresh_token=refresh_token
    )
    # print(client.session.token)
    
    # print(client.session.get('https://api.fitbit.com/1/user/-/profile.json').json())
    
    auth_url = client.authorize_token_url(
        scope='activity nutrition heartrate location nutrition profile settings sleep social weight',
        redirect_uri='http://localhost:8080'
    )
    print(auth_url)
