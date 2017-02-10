from __future__ import absolute_import, unicode_literals

import re
import urllib

import pyotp
import pytest
from qrcodegen import QrCode

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
    assert tfa.get_number_of_recovery_codes(user_id) == 0
    d.engine.execute("""
        INSERT INTO twofa_recovery_codes (userid, recovery_code)
        VALUES ( (%(userid)s), (%(code)s) )
    """, userid=user_id, code=security.generate_key(20))
    assert tfa.get_number_of_recovery_codes(user_id) == 1
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
        assert len(code['recovery_code']) == 20
        assert code['recovery_code'] in recovery_codes


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
    assert not tfa.is_recovery_code_valid(user_id, "a" * 20)


@pytest.mark.usefixtures('db')
def test_init():
    """
    Verify we get a usable 2FA Secret and QRCode from init()
    """
    user_id = db_utils.create_user()
    tfa_secret, tfa_qrcode = tfa.init(user_id)

    computed_uri = pyotp.TOTP(tfa_secret).provisioning_uri(d.get_display_name(user_id), issuer_name="Weasyl")
    qr = QrCode.encode_text(computed_uri, QrCode.Ecc.MEDIUM)
    qr_xml = qr.to_svg_str(4)
    # We only care about the content in the <svg> tags; strip '\n' to permit re.search to work
    qr_svg_only = re.search(r"<svg.*<\/svg>", qr_xml.replace('\n', '')).group(0)
    computed_qrcode = urllib.quote(qr_svg_only)
    # The QRcode we make locally should match that from init()
    assert tfa_qrcode == computed_qrcode
    # The tfa_secret from init() should be 16 characters, and work if passed in to pyotp.TOTP.now()
    assert len(tfa_secret) == 16
    assert len(pyotp.TOTP(tfa_secret).now()) == 6

    
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
    assert tfa.activate(user_id, tfa_secret, tfa_response)
    assert tfa_secret == d.engine.scalar("""
        SELECT twofa_secret
        FROM login
        WHERE userid = (%(userid)s)
    """, userid=user_id)


@pytest.mark.usefixtures('db')
def test_is_2fa_enabled():
    user_id = db_utils.create_user()
    
    # Code path 1: 2FA is not enabled
    assert not tfa.is_2fa_enabled(user_id)
    
    # Code path 2: 2FA is enabled
    d.engine.execute("""
        UPDATE login
        SET twofa_secret = (%(tfas)s)
        WHERE userid = (%(userid)s)
    """, userid=user_id, tfas=pyotp.random_base32())
    assert tfa.is_2fa_enabled(user_id)


@pytest.mark.usefixtures('db')
def test_deactivate():
    user_id = db_utils.create_user()
    tfa_secret = pyotp.random_base32()
    totp = pyotp.TOTP(tfa_secret)
    
    # Code path 1.1: 2FA enabled, deactivated by TOTP challenge-response code
    d.engine.execute("""
        UPDATE login
        SET twofa_secret = (%(tfas)s)
        WHERE userid = (%(userid)s)
    """, userid=user_id, tfas=tfa_secret)
    tfa_response = totp.now()
    print(type(tfa_response))
    assert tfa.deactivate(user_id, tfa_response)
    
    # Code path 1.2: 2FA enabled, deactivated by recovery code
    d.engine.execute("""
        UPDATE login
        SET twofa_secret = (%(tfas)s)
        WHERE userid = (%(userid)s)
    """, userid=user_id, tfas=tfa_secret)
    tfa_response = totp.now()
    recovery_code = security.generate_key(20)
    d.engine.execute("""
        INSERT INTO twofa_recovery_codes (userid, recovery_code)
        VALUES ( (%(userid)s), (%(code)s) )
    """, userid=user_id, code=recovery_code)
    assert tfa.deactivate(user_id, recovery_code)
    
    # Code path 2: 2FA enabled, failed deactivation (invalid `tfa_response` (code or TOTP token))
    d.engine.execute("""
        UPDATE login
        SET twofa_secret = (%(tfas)s)
        WHERE userid = (%(userid)s)
    """, userid=user_id, tfas=tfa_secret)
    assert not tfa.deactivate(user_id, "000000")
    assert not tfa.deactivate(user_id, "a" * 20)


@pytest.mark.usefixtures('db')
def test_verify():
    user_id = db_utils.create_user()
    tfa_secret = pyotp.random_base32()
    totp = pyotp.TOTP(tfa_secret)
    recovery_code = security.generate_key(20)
    d.engine.execute("""
        UPDATE login
        SET twofa_secret = (%(tfas)s)
        WHERE userid = (%(userid)s)
    """, userid=user_id, tfas=tfa_secret)
    d.engine.execute("""
        INSERT INTO twofa_recovery_codes (userid, recovery_code)
        VALUES ( (%(userid)s), (%(code)s) )
    """, userid=user_id, code=recovery_code)
    
    # Code path 1: TOTP token matches current expected value (Successful Verification)
    tfa_response = totp.now()
    assert tfa.verify(user_id, tfa_response)
    
    # Code path 1.1: TOTP token does not match current expected value (Unsuccessful Verification)
    assert not tfa.verify(user_id, "000000")
    
    # Code path 2: Recovery code does not match stored value (Unsuccessful Verification)
    assert not tfa.verify(user_id, "a" * 20)
    
    # Code path 2.1: Recovery code matches a stored recovery code (Successful Verification)
    assert tfa.verify(user_id, recovery_code)
    
    # Code path 2.2: Recovery codes are consumed upon use (consumed in 2.1) (Unsuccessful Verification)
    assert not tfa.verify(user_id, recovery_code)
