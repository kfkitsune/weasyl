from __future__ import absolute_import

import pyotp
import pytest

from weasyl import define as d
from weasyl import two_factor_auth as tfa
from weasyl.test import db_utils


@pytest.mark.usefixtures('db', 'cache')
def test_enable_2fa_totp(app):
    user = db_utils.create_user(username='user1', password='password1')

    resp = app.get('/')
    pass
