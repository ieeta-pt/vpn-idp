import threading
import time
import webbrowser
import socket
import os
from flask import Flask, redirect, request
import logging
from dotenv import load_dotenv

load_dotenv()

# Logging configuration
logging.basicConfig(
    format='%(asctime)s %(levelname)-8s %(message)s',
    level=logging.INFO,
    datefmt='%d-%m-%Y %H:%M:%S')


# Get environment variables
VPN_SERVER_URL = os.getenv('VPN_SERVER_URL')
VPN_CLIENT_WG_PUB_KEY = os.environ.get('VPN_CLIENT_WG_PUB_KEY')


def initial_logging(port):
    logging.info(f"Local server listening on port {port}")
    logging.info(f"Launching browser...")
    logging.info(f"{VPN_SERVER_URL}/accounts/login/?port={port}")
    webbrowser.open(
        f"{VPN_SERVER_URL}/accounts/login/?port={port}")


class MyFlaskApp(Flask):
    def run(self, host=None, port=None, debug=None, load_dotenv=True, **options):
        if not self.debug or os.getenv('WERKZEUG_RUN_MAIN') == 'true':
            with self.app_context():
                initial_logging(port)
        super(MyFlaskApp, self).run(host=host, port=port,
                                    debug=debug, load_dotenv=load_dotenv, **options)


# Initialize app
app = MyFlaskApp(__name__)

# Find available port
sock = socket.socket()
sock.bind(('', 0))
port = sock.getsockname()[1]
sock.close()


def create_vpn(params):
    """
    Simulates the instatiation of a WireGuard VPN connection
    based on the parameters recieved from the VPN Server.
    """
    
    if params.get('machine_id'):
        logging.info(f"Machine ID: {params.get('machine_id')}")
    logging.info(f"Client WG ipv4: {params.get('machine_wg_ipv4_address')}")
    logging.info(f"Client WG ipv4 pool: {params.get('machine_wg_ipv4_address_pool')}")
    logging.info(f"Client WG pub key: {params.get('machine_wg_pub_key')}")
    logging.info(f"Server WG pub key: {params.get('server_wg_pub_key')}")
    logging.info(f"Server WG public endpoint: {params.get('server_wg_public_endpoint')}")
    logging.info("VPN creation Thread starting (simulation)...")
    time.sleep(5)
    logging.info("VPN creation Thread finishing.")


@app.route('/login_callback')
def redirect_to_vpn_server():
    """
    Redcieves the callback from the IdP callback and redirects it to
    the real OAuth2.0 client, aka the VPN Server. If the response
    contains a code (Auth Grant flow), it adds the code to the
    redirection request.
    """

    code = request.args.get("code")
    logging.info("Recieved redirect from IdP, redirecting token fragment to the VPN Server...")
    if code:
        logging.info("Found code, adding it to redirect...")
        return redirect(f'{VPN_SERVER_URL}/accounts/login_callback/?code={code}&wg_pub_key={VPN_CLIENT_WG_PUB_KEY}')
    return redirect(f'{VPN_SERVER_URL}/accounts/login_callback/?wg_pub_key={VPN_CLIENT_WG_PUB_KEY}')


@app.route('/vpn_parameters')
def recieve_vpn_parameters():
    """
    Endpoint where the VPN Server sends the final VPN parameters
    upon successful authentication. These parameters allow the client
    to initiate the VPN connection.
    """
    
    logging.info("Recieved parameters from browser.")
    create_vpn_job = threading.Thread(target=create_vpn, args=(request.args,))
    create_vpn_job.start()
    return 'Login successful. You can close this window now.'


app.run(host="127.0.0.1", port=port)
