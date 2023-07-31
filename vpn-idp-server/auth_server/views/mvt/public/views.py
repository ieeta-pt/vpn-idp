from django.shortcuts import render
from django.contrib.auth import login
from django.http import HttpResponseRedirect
import pkce
from datetime import datetime
from cryptography.fernet import Fernet
from accounts.models import User, WireguardMachine, IdentityProvider
from auth_server.forms import *
from auth_server.utils.utils import retrieve_auth_gov_id, retrieve_google_access_token, retrieve_google_id, transform_resource, get_random_string
import os
import urllib.parse


# Logging
import logging
logging.basicConfig(
    format='%(asctime)s %(levelname)-8s %(message)s',
    level=logging.INFO,
    datefmt='%d-%m-%Y %H:%M:%S')


# Where the IdP sends callbacks
os.environ.setdefault('LOCAL_MACHINE_CALLBACK_ADDRESS',
                      'http://127.0.0.1:{}/login_callback')
# Where the VPN parameters are sent after authentication
os.environ.setdefault('LOCAL_MACHINE_PARAMETERS_ADDRESS',
                      'http://127.0.0.1:{}/vpn_parameters')


# Ephemeral symetric key used to cypher cookies
f_key = Fernet(os.environ.get('COOKIE_CYPHER_KEY').encode(encoding='UTF-8'))


# Endpoint: /accounts/login/
def login_view(request):
    """
    Web page that allows a client to choose the IdP to use.
    The request must include the VPN Client port in the URL
    parameters.
    """

    if request.method == "GET":

        # Retrieve VPN Client port on local computer
        client_callback_port = request.GET.get('port')

        # Show error if the required parameters are not present
        if client_callback_port:

            # TODO: Check if port is a valid port

            # Build response based on request
            response = render(request=request, template_name="login.html")

            # Cypher parameters with symetric key created on webserver launch (temporary cypher)
            cyphered_client_callback_port = f_key.encrypt(
                client_callback_port.encode(encoding='UTF-8')).decode(encoding='UTF-8')

            # Set cookie with cyphered parameters, with max age of 5 minutes (login max time)
            response.set_cookie(
                'vpnidp_1', cyphered_client_callback_port, max_age=300)

            return response
    else:
        return render(request=request, template_name="error.html", context={"error": "Method not allowed for this endpoint."}, status=405)
    return render(request=request, template_name="error.html", context={"error": "Must provide all the URL parameters (port)"}, status=400)


# accounts/login/<slug:auth_idp>/
def login_idp_view(request, auth_idp=None):
    """
    Redirects the user to the external IdP authorization endpoint.
    The request is built with the OAuth2.0 mandatory parameters, using
    the OAuth2.0 client credentials of this VPN Server instance for that
    particular IdP, which are saved in the database. The redirect URI
    parameter given to the IdP is the VPN Client local machine endpoint
    that is listening:
    http://127.0.0.1:{port}/login_callback
    """
    if request.method == "GET":

        # Retrieve cyphered VPN Client port stored in request cookie
        cyphered_client_callback_port = request.COOKIES.get('vpnidp_1')

        # Return error page if there is no cookie
        if not cyphered_client_callback_port:
            return render(request=request, template_name="error.html", context={"error": "vpnidp_1 cookie was not provided."}, status=400)

        # Decypher port with symetric key created on webserver launch
        client_callback_port = f_key.decrypt(cyphered_client_callback_port.encode(
            encoding='UTF-8')).decode(encoding='UTF-8')

        # TODO: Check if port decyphered is valid

        # Build IdP authorization request
        idp_object = IdentityProvider.objects.filter(name=auth_idp).first()
        if not idp_object:
            return render(request=request, template_name="error.html", context={"error": "The chosen IdP is unknown."}, status=404)

        # Local machine endpoint -> http://127.0.0.1:{port}/login_callback
        redirect_uri = os.environ.get(
            'LOCAL_MACHINE_CALLBACK_ADDRESS').format(client_callback_port)

        authorization_params = {
            "client_id": idp_object.client_id,
            "scope": idp_object.scope,
            "response_type": idp_object.response_type,
            "redirect_uri": redirect_uri
        }

        # Generate PKCE verifier (tailored to IdP)
        code_verifier = None
        if idp_object.name == "google":
            code_verifier = pkce.generate_code_verifier(length=128)
            authorization_params["code_challenge"] = pkce.get_code_challenge(
                code_verifier)
            authorization_params["code_challenge_method"] = idp_object.code_challange_method

        authorization_redirect = idp_object.auth_endpoint + \
            "?" + urllib.parse.urlencode(authorization_params)
        response = HttpResponseRedirect(redirect_to=authorization_redirect)

        logging.info(f"AUTH REQUEST W/ PKCE: {authorization_redirect}")

        # Cypher IdP chosen and save it on other cookie
        auth_idp += "#" + get_random_string(31 - len(auth_idp))
        cyphered_client_auth_idp = f_key.encrypt(
            auth_idp.encode(encoding='UTF-8')).decode(encoding='UTF-8')
        response.set_cookie('vpnidp_2', cyphered_client_auth_idp, max_age=300)

        # Add PKCE verifier
        if code_verifier:
            cyphered_code_verifier = f_key.encrypt(
                code_verifier.encode(encoding='UTF-8')).decode(encoding='UTF-8')
            response.set_cookie(
                'vpnidp_3', cyphered_code_verifier, max_age=300)

        return response

    else:
        return render(request=request, template_name="error.html", context={"error": "Method not allowed for this endpoint."}, status=405)


# accounts/login_callback/
def login_callback_view(request):
    """
    Endpoint to which the VPN Client redirects the callback recieved
    by the external IdP.
    The user's identification is retrieved from the chosen IdP according to
    it's specific OAuth2.0 flow implementation.
    After the user is authenticated, the provided WireGuard Public Key
    and Machine ID are used to create or update a WireGuard machine for
    that user.
    The response contains all the information that the VPN Client needs in
    order to connect to this VPN Server instance using WireGuard.
    """

    # AUTHENTICATION

    start_time = datetime.now()
    logging.info(f"Entered /login_callback/ at t={start_time}")

    # Retrieve cyphered VPN Client port stored in request cookie
    cyphered_client_callback_port = request.COOKIES.get('vpnidp_1')
    cyphered_client_auth_idp = request.COOKIES.get('vpnidp_2')

    # Return error page if the port cookie is not present
    if not cyphered_client_callback_port:
        return render(request=request, template_name="error.html", context={"error": "vpnidp_1 cookie was not provided."}, status=400)

    # Return error page if the client idp cookie is not present
    if not cyphered_client_auth_idp:
        return render(request=request, template_name="error.html", context={"error": "vpnidp_1 cookie was not provided."}, status=400)

    # Decypher port with symetric key created on webserver launch
    client_callback_port = f_key.decrypt(cyphered_client_callback_port.encode(
        encoding='UTF-8')).decode(encoding='UTF-8')
    client_auth_idp = f_key.decrypt(cyphered_client_auth_idp.encode(
        encoding='UTF-8')).decode(encoding='UTF-8').split("#")[0]

    logging.info(
        f"vpnidp_1 -> {cyphered_client_callback_port} -> {client_callback_port}")
    logging.info(
        f"vpnidp_2 -> {cyphered_client_auth_idp} -> {client_auth_idp}")

    # TODO: Validate decyphered port and auth id

    user_idp_id = None

    # Google OAuth2.0 flow
    if client_auth_idp == "google":

        # Google's auth code comes as a URL query argument
        # Retrieve it and continue the OAuth2.0 flow

        if request.method != "GET":
            return render(request=request, template_name="error.html", context={"error": "Method not allowed for this IdP."}, status=405)

        # Retrieve authorization code from URL
        code = request.GET.get('code')

        # Retrieve PKCE identifier from cyphered cookie
        cyphered_code_verifier = request.COOKIES.get('vpnidp_3')

        # Return error page if the PKCE cookie is not present
        if not cyphered_code_verifier:
            return render(request=request, template_name="error.html", context={"error": "vpnidp_3 cookie was not provided."}, status=400)

        # Decypher port with symetric key created on webserver launch
        code_verifier = f_key.decrypt(cyphered_code_verifier.encode(
            encoding='UTF-8')).decode(encoding='UTF-8')

        # Retrieve access token using authorization code and before used redirect uri
        redirect_uri = os.environ.get(
            'LOCAL_MACHINE_CALLBACK_ADDRESS').format(client_callback_port)
        access_token = retrieve_google_access_token(
            auth_code=code, redirect_uri=redirect_uri, code_verifier=code_verifier)

        # Retrieve user id
        user_idp_id = retrieve_google_id(access_token)

        start_time_2 = datetime.now()
        logging.info(f"Retrieved user ID at t={start_time_2}")

    # Autenticacao.gov OAuth2.0 flow
    elif client_auth_idp == "auth_gov":

        # Autenticacao.gov sends an access token as a URL fragment (implicit grant)
        # Retrieve it with JavaScript page and continue the OAuth2.0 flow

        access_token = None

        # Provide page that retrieves access token from URL fragment and submits back a form with it
        if request.method == 'GET':
            form = Oauth2ImplicitTokenForm()
            return render(request=request, template_name="oauth2token.html", context={"oauth2_form": form})

        # Retrieve access token from form submitted
        elif request.method == 'POST':
            form = Oauth2ImplicitTokenForm(request.POST)
            if form.is_valid():
                access_token = form.cleaned_data.get('oauth2_token')
        else:
            return render(request=request, template_name="error.html", context={"error": "Method not allowed for this endpoint."}, status=405)

        if not access_token:
            return render(request=request, template_name="error.html", context={"error": "vpnidp_1 cookie was not provided."}, status=400)

        # Retrieve user id
        user_idp_id = retrieve_auth_gov_id(access_token)

    if user_idp_id is None:
        return render(request=request, template_name="error.html", context={"error": "Identity was not provided by IdP."}, status=404)

    # Unique user ID, independent from the IdP
    user_id = transform_resource(user_idp_id + "#" + client_auth_idp)

    client_wg_pub_key = request.GET.get('wg_pub_key')
    client_machine_id = request.GET.get('machine_id')
    logging.info(f"client_wg_pub_key -> {client_wg_pub_key}")
    logging.info(f"client_machine_id -> {client_machine_id}")

    # WireGuard parameters

    # Login user using unique ID, create user if doesn't exist
    user = User.objects.filter(username=user_id).first()
    existing_user = True
    if not user:
        user = User(username=user_id)

        # If the user doesn't exist, create address space for him
        # TODO: Actually generate address pool from available address pools
        user.wg_ipv4_address_pool = "ip_address_pool"
        user.save()
        existing_user = False
    login(request, user)

    machine = None

    # Always provide wg pub key and machine id, being existing user or not
    if not (client_machine_id and client_wg_pub_key):
        render(request=request, template_name="error.html", context={
               "error": "Must provide machine_id and wg_pub_key."}, status=400)

    if not existing_user:

        # Create machine for user and associate an address to it
        # and the given wg pub key

        # TODO: Create ipv4 address from user's adress pool
        client_wg_ipv4_address = "new_ip_of_pool"

        machine = WireguardMachine(
            machine_id=client_machine_id,
            wg_ipv4_address=client_wg_ipv4_address,
            wg_pub_key=client_wg_pub_key,
            user=user
        )
        machine.save()

    else:

        # Check if machine given is already registred to that user
        machine = WireguardMachine.objects.filter(
            machine_id=client_machine_id).first()

        # It it's not, create it
        if not machine:

            # TODO: Create ipv4 address from user's adress pool
            client_wg_ipv4_address = "new_ip_of_pool"

            machine = WireguardMachine(
                machine_id=client_machine_id,
                wg_ipv4_address=client_wg_ipv4_address,
                wg_pub_key=client_wg_pub_key,
                user=user
            )
            machine.save()

        # if it is, update wg pub key if the provided key is different
        else:
            machine.wg_pub_key = client_wg_pub_key
            machine.save()

    parameters = {
        'machine_id': machine.machine_id,
        'machine_wg_ipv4_address': machine.wg_ipv4_address,
        'machine_wg_ipv4_address_pool': user.wg_ipv4_address_pool,
        'machine_wg_pub_key': machine.wg_pub_key,
        # TODO: Change to actual VPN Server WireGuard pub key
        'server_wg_pub_key': "uGHdwr5zgQkTuwBmfZPCQCPHmguKZRyRUT6EZwhclFU=",
        # TODO: Change to actual VPN Server WireGuard public endpoint
        'server_wg_public_endpoint': "vpn_server_wireguard_public_endpoint"
    }

    redirect_to = os.environ.get('LOCAL_MACHINE_PARAMETERS_ADDRESS').format(
        client_callback_port) + "?" + urllib.parse.urlencode(parameters)

    stop_time = datetime.now()
    logging.info(f"Returned machine params at t={stop_time}")

    return HttpResponseRedirect(redirect_to=redirect_to)

    # FOR APP PROTOCOLS METHOD
    # logging.info(f"LOCATION: {location}")
    # res = HttpResponse(location, status=302)
    # res['Location'] = location
