import uuid
from django.contrib.auth.models import AbstractUser
from django.db import models

IDP_TYPE_CHOICES = (
    ('auth_code', 'auth_code'),
    ('implicit_grant', 'implicit_grant')
)

IDP_RESPONSE_TYPE_CHOICES = (
    ('token', 'token'),
    ('code', 'code')
)

class User(AbstractUser):
    pass
    wg_ipv4_address_pool = models.CharField(default=None, null=True, blank=True, max_length=18)  # Pool of user's addresses inside VPN
    
    def __str__(self):
        return self.username

class WireguardMachine(models.Model):
    machine_id = models.CharField(max_length=256, editable=False,default=None, null=True)
    wg_ipv4_address = models.CharField(default=None, null=True, blank=True, max_length=15)
    wg_pub_key = models.CharField(default=None, null=True, blank=True, max_length=256)  # WireGuard Public Key
    user = models.ForeignKey(User, on_delete=models.CASCADE)

class IdentityProvider(models.Model):
    name = models.CharField(null=True, max_length=255)
    type = models.CharField(choices=IDP_TYPE_CHOICES, null=False, max_length=15)
    client_id = models.CharField(max_length=255, null=False)
    client_secret = models.CharField(max_length=255, null=True)
    auth_endpoint = models.URLField(max_length=255, null=True)
    token_endpoint = models.URLField(max_length=255, null=True)
    scope = models.CharField(max_length=255, null=False)
    response_type = models.CharField(choices=IDP_RESPONSE_TYPE_CHOICES, max_length=255, null=True)
    redirect_uri = models.URLField(max_length=255, null=True)
    code_challange_method = models.CharField(null=True, max_length=255)

