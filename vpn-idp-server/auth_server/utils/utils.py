# Utils
import json
import urllib
import requests
from django.contrib.auth.hashers import make_password
import string
import random

# Models
from accounts.models import IdentityProvider

# Logging
import logging
logging.basicConfig(
    format='%(asctime)s %(levelname)-8s %(message)s',
    level=logging.INFO,
    datefmt='%d-%m-%Y %H:%M:%S')


# ------------- GOOGLE -------------

def retrieve_google_access_token(auth_code, redirect_uri, code_verifier):
    """
    Google's OAuth2.0 process to Exchange authorization code for refresh and access tokens:
    https://developers.google.com/identity/protocols/oauth2/native-app#exchange-authorization-code

    Return None if any problem retrieving access token.
    """

    access_token = None

    google_idp_object = IdentityProvider.objects.filter(name="google").first()

    if not google_idp_object:
        return None

    # Build request to /token endpoint
    url = google_idp_object.token_endpoint
    headers = {
        'Host': 'oauth2.googleapis.com',
        'Content-type': 'application/x-www-form-urlencoded'
    }

    body = {
        'code': auth_code,
        'code_verifier' : code_verifier,
        'client_id': google_idp_object.client_id,
        'client_secret': google_idp_object.client_secret,
        'redirect_uri': redirect_uri,
        'grant_type': 'authorization_code',
    }

    try:
        r = requests.post(url, data=body, headers=headers)

        # Retrieve access token from response
        credentials = json.loads(r.text)
        logging.info(f"Credentials: {credentials}")
        access_token = credentials['access_token']
    except Exception as e:
        return None

    return access_token


def retrieve_google_id(access_token):
    """
    Google's OAuth2.0 process to Calling Google APIs:
    https://developers.google.com/identity/protocols/oauth2/native-app#callinganapi

    Return None if any problem retrieving user id.
    """
    google_id = None
    try:

        # Simple get to API carrying Bearer token
        headers = {'Authorization': 'Bearer {}'.format(access_token)}
        resource_uri = 'https://www.googleapis.com/oauth2/v3/userinfo'
        r_resource = requests.get(resource_uri, headers=headers)
        google_id = json.loads(r_resource.text)["email"]
    except Exception as e:
        return None
    return google_id


# ------------- AUTENTICACAO.GOV -------------


def retrieve_auth_gov_id(access_token):
    """
    Autenticacao.gov's AOuth2.0 process to retrieve Portuguese Citizen attributes:
    https://github.com/amagovpt/doc-AUTENTICACAO

    Return None if any problem retrieving user id.
    """

    auth_gov_id = None

    cmd_attribute_manager_url = 'https://preprod.autenticacao.gov.pt/oauthresourceserver/api/AttributeManager'

    # Ask CMD oauthresourceserver for authenticationContextId
    try:
        body_json = {"token": access_token, "attributesName": [
            "http://interop.gov.pt/MDC/Cidadao/NIC"]}
        attribute_manager_request = requests.post(
            cmd_attribute_manager_url, json=body_json)
        authenticationContextId = json.loads(attribute_manager_request.text)[
            "authenticationContextId"]

        # Use oauth2 token and authenticationContextId to retrieve resources
        params = {'token': access_token,
                  'authenticationContextId': authenticationContextId}
        resources_url = cmd_attribute_manager_url + \
            '?' + urllib.parse.urlencode(params)
        resources_request = requests.get(resources_url)
        auth_gov_id = json.loads(resources_request.text)[0]["value"]
    except Exception as e:
        return None
    return auth_gov_id


# ------------- OTHER -------------


def transform_resource(resource):
    """
    SHA256 hash using fixed salt.
    """

    # One-way expensive transformation
    return make_password(resource, hasher='pbkdf2_sha256', salt='1AAF047H3W1N')


def get_random_string(length):
    """
    Generate random trash string with given length.
    """

    # Choose from all lowercase letter
    letters = string.ascii_letters
    return ''.join(random.choice(letters) for i in range(length))
