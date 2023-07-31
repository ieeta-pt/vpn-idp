#!/usr/bin/env python3
"""Django's command-line utility for administrative tasks."""
import os
import sys
from cryptography.fernet import Fernet


def main():
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'auth_server.settings')
    os.environ.setdefault('COOKIE_CYPHER_KEY', Fernet.generate_key().decode(encoding='UTF-8'))
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()
