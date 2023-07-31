from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib import messages

# Logging
import logging
logging.basicConfig(
    format='%(asctime)s %(levelname)-8s %(message)s',
    level=logging.INFO,
    datefmt='%d-%m-%Y %H:%M:%S')


@login_required
def logout_view(request):
    """
    Allows a logged-in user to log out.
    """

    logout(request)
    messages.info(request, "You have successfully logged out.")
    return redirect("profile")
