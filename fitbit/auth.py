import fitbit.api as fitbit
import os
import json
from dotenv import load_dotenv
load_dotenv()

client_id = os.environ.get("FITBIT_CLIENT_ID")
client_secret = os.environ.get("FITBIT_CLIENT_SECRET")

def get_tokens():
    try:
        with open('token.json', 'r') as f:
            tokens = json.load(f)
            access_token = tokens['access_token']
            refresh_token = tokens['refresh_token']
            return access_token, refresh_token
    except FileNotFoundError:
        print("token.json not found")
        return None

def get_fitbit_client(access_token, refresh_token):
    return fitbit.Fitbit(client_id=client_id, client_secret=client_secret,
                         access_token=access_token, refresh_token=refresh_token)

