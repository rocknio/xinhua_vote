"""
WSGI config for xinhua_vote project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/1.10/howto/deployment/wsgi/
"""

import os
import sys

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "xinhua_vote.settings")
sys.path.append('C:/xinhua_vote')

application = get_wsgi_application()
