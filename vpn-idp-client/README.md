# vpn-idp-client

## Introduction

VPN Client that authenticates with a VPN Server using external IdPs.

This repository integrates part of the VPN solution proposed in my MSc thesis:

- D. Mortágua, "Authentication in VPNs and 802.1X networks with Identity Providers," M.S. thesis, Department of Electronics, Telecommunications and Informatics, University of Aveiro, Aveiro, 2023. [Online]. Available: soon.

### TL;DR:

This work presents a streamlined VPN solution that utilizes external IdPs for client user authentication and leverages the OAuth 2.0 authorization process for WireGuard key negotiation, ensuring that only authenticated peers can establish a VPN connection.

This piece of code implements the VPN Client module. The ```presentation.pdf``` file includes a brief explanaition of the architecture and communication implemented.

## Installation:
Set up the python environment by running:
```
python3 -m venv venv
source venv/bin/activate
python3 -m pip install -r requirements.txt
```

You need to set up the following environment variables (```.env``` file in root directory):
``````
VPN_SERVER_URL=<your_vpn_server_url>
VPN_CLIENT_WG_PUB_KEY=<your_vpn_client_wireguard_pub_key>
``````

Finally, run the client:
```
python3 client.py
```
