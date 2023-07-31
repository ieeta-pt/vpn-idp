# vpn-idp-server

## Introduction

VPN server that allows a VPN client to authenticate via an external Identity Provider, using OAuth2.0, avoiding the usual ID/Password authentication.

This repository integrates part of the VPN solution proposed in my MSc thesis:

- D. Mortágua, "Authentication in VPNs and 802.1X networks with Identity Providers," M.S. thesis, Department of Electronics, Telecommunications and Informatics, University of Aveiro, Aveiro, 2023. [Online]. Available: soon.

## Introduction

### TL;DR:

This work presents a streamlined VPN solution that utilizes external IdPs for client user authentication and leverages the OAuth 2.0 authorization process for WireGuard key negotiation, ensuring that only authenticated peers can establish a VPN connection.

This piece of code implements the VPN Server module. The ```presentation.pdf``` file includes a brief explanaition of the architecture and communication implemented.

## Installation:

Set up the python environment by running:
```
python3 -m venv venv
source venv/bin/activate
python3 -m pip install -r requirements.txt
```

Apply the Django migrations:
```
python3 manage.py makemigrations
python3 manage.py migrate
```

Create the Django admin user:
```
python3 manage.py createsuperuser --username admin
```

As this server acts like a OAuth2.0 client, it needs to hold credentials regarding the supported IdPs (client ID, client secret, etc...). This Django project is ready to hold a sqlite3 table that holds these credentials, according to the model ```IdentityProvider``` in ```accounts/models.py```.

In order to facilitate the import of an IdP, you can set up a OAuth2.0 client (for example, [Google ID](https://developers.google.com/identity/protocols/oauth2)) and import it as a Django fixture.

Example of a fixture file ```fixtures/idps.json``` holding 1 IdP configuration:
```json
[
    {
        "model": "accounts.identityprovider",
        "pk": 1,
        "fields": {
            "name" : "google",
            "type": "auth_code",
            "client_id": "********",
            "client_secret": "********",
            "auth_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_endpoint": "https://oauth2.googleapis.com/token",
            "scope": "https://www.googleapis.com/auth/userinfo.email",
            "response_type": "code",
            "redirect_uri": null,
            "code_challange_method" : "S256"
        }
    }
]
```

You can import the fixture file as follows:
```bash
python3 manage.py loaddata fixtures/idps.json --app accounts.IdentityProvider
```
Finally, you can run the server:
```bash
python3 manage.py runserver 127.0.0.1:8000
```
