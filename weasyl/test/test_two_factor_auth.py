from __future__ import unicode_literals, absolute_import

import base64

import pyotp
import pytest
import qrcode
import qrcode.image.svg

from libweasyl import security
from weasyl import define as d
from weasyl import two_factor_auth as tfa
from weasyl.test import db_utils


@pytest.mark.usefixtures('db')
def test_get_number_of_recovery_codes():
    user_id = db_utils.create_user()
    
    # This /should/ be zero right now, but verify this for test environment sanity.
    assert 0 == d.engine.scalar("""
        SELECT COUNT(*)
        FROM twofa_recovery_codes
        WHERE userid = (%(userid)s)
    """, userid=user_id)
    assert tfa.get_number_of_recovery_codes(userid) == 0
    d.engine.execute("""
        INSERT INTO twofa_recovery_codes (userid, recovery_code)
        VALUES ( (%(userid)s), (%(code)s) )
    """, userid=user_id, code=security.generate_key(20))
    assert tfa.get_number_of_recovery_codes(userid) == 1
    d.engine.execute("""
        DELETE FROM twofa_recovery_codes
        WHERE userid = (%(userid)s)
    """, userid=user_id)
    assert tfa.get_number_of_recovery_codes(user_id) == 0


@pytest.mark.usefixtures('db')
def test_generate_recovery_codes():
    user_id = db_utils.create_user()

    recovery_codes = tfa.generate_recovery_codes(user_id)
    assert len(recovery_codes) == 10

    query = d.engine.execute("""
        SELECT recovery_code
        FROM twofa_recovery_codes
        WHERE userid = (%(userid)s)
    """, userid=user_id).fetchall()
    for code in query:
        assert code in recovery_codes


@pytest.mark.usefixtures('db')
def test_is_recovery_code_valid():
    user_id = db_utils.create_user()
    recovery_code = security.generate_key(20)
    d.engine.execute("""
        INSERT INTO twofa_recovery_codes (userid, recovery_code)
        VALUES ( (%(userid)s), (%(code)s) )
    """, userid=user_id, code=recovery_code)

    # Code path 1: Recovery code is valid (code is consumed)
    assert tfa.is_recovery_code_valid(user_id, recovery_code)

    # Code path 2: Recovery code invalid (because code was consumed)
    assert not tfa.is_recovery_code_valid(user_id, recovery_code)

    # Code path 2.1: Recovery code is invalid (code was not a real code)
    assert tfa.is_recovery_code_valid(user_id, "a" * 19)



@pytest.mark.usefixtures('db')
def test_init():
    """
    Verify we get a usable 2FA Secret and QRCode from init()
    """
    user_id = db_utils.create_user()
    tfa_secret, tfa_qrcode = tfa.init(user_id)

    computed_uri = pyotp.TOTP(tfa_secret).provisioning_uri(d.get_display_name(user_id), issuer_name="Weasyl")
    qr_factory = qrcode.image.svg.SvgPathFillImage
    computed_qrcode = qrcode.make(computed_uri, image_factory=qr_factory)
    print(computed_qrcode)

    # The QRcode we make locally should match that from init()
    assert tfa_qrcode == computed_b64_qrcode
    # The tfa_secret from init() should be 16 characters, and work if passed in to pyotp.TOTP.now()
    assert len(tfa_secret) == 16
    assert len(pyotp.TOTP(tfa_secret).now()) == 6
    assert 0


@pytest.mark.usefixtures('db')
def test_init_verify_tfa():
    user_id = db_utils.create_user()
    tfa_secret, _ = tfa.init(user_id)

    # Code path 1: Invalid initial verification
    assert not tfa.init_verify_tfa(user_id, tfa_secret, "000000")

    # Code path 2: Valid initial verification
    totp = pyotp.TOTP(tfa_secret)
    tfa_response = totp.now()
    test_tfa_secret, test_recovery_codes = tfa.init_verify_tfa(user_id, tfa_secret, tfa_response)
    assert tfa_secret == test_tfa_secret
    assert len(test_recovery_codes) == 10


@pytest.mark.usefixtures('db')
def test_activate():
    user_id = db_utils.create_user()
    tfa_secret = pyotp.random_base32()
    totp = pyotp.TOTP(tfa_secret)

    # Code path 1: Failed validation between tfa_secret/tfa_response
    assert not tfa.activate(user_id, tfa_secret, "000000")
    # Verify 2FA is not active
    assert not d.engine.scalar("""
        SELECT twofa_secret
        FROM login
        WHERE userid = (%(userid)s)
    """, userid=user_id)

    # Code path 2: Validation successful, and tfa_secret written into user's `login` record
    tfa_response = totp.now()
    assert tfa.activate(userid, tfa_secret, tfa_response)
    assert tfa_secret == d.engine.scalar("""
        SELECT twofa_secret
        FROM login
        WHERE userid = (%(userid)s)
    """, userid=user_id)


@pytest.mark.usefixtures('db')
def test_deactivate():
    pass


@pytest.mark.usefixtures('db')
def test_verify():
    pass
