#!/usr/bin/env python
import cherrypy
import json
import os
import sys
import threading
import traceback
import webbrowser
from fitbit.auth import FitbitOauth2Client
from oauthlib.oauth2.rfc6749.errors import MismatchingStateError, MissingTokenError
from dotenv import load_dotenv

load_dotenv()

class OAuth2Server:
    def __init__(self, client_id, client_secret,
                 redirect_uri='http://127.0.0.1:8080/'):
        """ Initialize the FitbitOauth2Client """
        self.success_html = """
            <h1>You are now authorized to access the Fitbit API!</h1>
            <br/><h3>You can close this window</h3>"""
        self.failure_html = """
            <h1>ERROR: %s</h1><br/><h3>You can close this window</h3>%s"""
        self.fitbit = FitbitOauth2Client(
            client_id,
            client_secret,
            redirect_uri=redirect_uri
        )

    def browser_authorize(self):
        """
        Open a browser to the authorization url and spool up a CherryPy
        server to accept the response
        """
        url, _ = self.fitbit.authorize_token_url()
        # Open the web browser in a new thread for command-line python
        threading.Timer(1, webbrowser.open, args=(url,)).start()
        cherrypy.quickstart(self)

    @cherrypy.expose
    def index(self, state=None, code=None, error=None):
        """
        Receive a Fitbit response containing a verification code. Use the code
        to fetch the access_token.
        """
        error = None
        if code:
            try:
                self.fitbit.fetch_access_token(code)
            except MissingTokenError:
                error = self._fmt_failure(
                    'Missing access token parameter.</br>Please check that '
                    'you are using the correct client_secret')
            except MismatchingStateError:
                error = self._fmt_failure('CSRF Warning! Mismatching state')
        else:
            error = self._fmt_failure('Unknown error while authenticating')
        # Use a thread to shutdown cherrypy so we can return HTML first
        self._shutdown_cherrypy()
        return error if error else self.success_html

    def _fmt_failure(self, message):
        tb = traceback.format_tb(sys.exc_info()[2])
        tb_html = '<pre>%s</pre>' % ('\n'.join(tb)) if tb else ''
        return self.failure_html % (message, tb_html)

    def _shutdown_cherrypy(self):
        """ Shutdown cherrypy in one second, if it's running """
        if cherrypy.engine.state == cherrypy.engine.states.STARTED:
            threading.Timer(1, cherrypy.engine.exit).start()


if __name__ == '__main__':
    client_id = os.getenv('FITBIT_CLIENT_ID')
    client_secret = os.getenv('FITBIT_CLIENT_SECRET')
    
    server = OAuth2Server(
        client_id,
        client_secret
    )
    server.browser_authorize()

    
    with open('token.json', 'w') as f:
        json.dump(server.fitbit.session.token, f)   
