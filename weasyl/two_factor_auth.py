"""
Module for handling 2FA-related functions.
"""
from __future__ import absolute_import

import base64

import arrow
import pyotp
import qrcode
import qrcode.image.svg

from libweasyl import security
from weasyl import define as d
from weasyl import login

# Number of recovery codes to provide the user
_TFA_RECOVERY_CODES = 10


def init(userid):
    """
    Initialize 2FA for a user by generating and returning a 2FA secret key.

    When a user opts-in to 2FA, this function generates the necessary 2FA secret,
    and QRcode.

    Parameters:
        userid: The userid of the calling user.

    Returns: A tuple in the format of (tfa_secret, tfa_qrcode), where:
        tfa_secret: The 16 character pyotp-generated secret.
        tfa_qrcode: Base64-encoded QRcode (SVG/PNG?) containing necessary information for
        Google Authenticator use. This is used in a dataURI to display an ephemeral qrcode.
    """
    tfa_secret = pyotp.random_base32()
    totp_uri = pyotp.TOTP(tfa_secret).provisioning_uri(d.get_display_name(userid), issuer_name="Weasyl")
    # Generate the QRcode
    qrc_factory = qrcode.image.svg.SvgPathFillImage
    tfa_qrcode = base64.b64encode(qrcode.make(totp_uri, image_factory=qrc_factory))
    # Return the tuple
    return tfa_secret, tfa_qrcode


def init_verify(userid, tfa_secret, tfa_response):
    """
    Verify that the user has successfuly set-up 2FA, and enable 2FA.

    Upon verification by pyotp that the 2FA response corresponds to the 2FA
    secret, store the 2FA secret in the user's login record, thus enabling
    2FA for the user.

    Parameters:
        userid: The userid of the calling user.
        tfa_secret: The 2FA secret generated from tfa_init(); retrieved from the
        verification page's form information.
        tfa_response: The 2FA challenge-response code to verify against tfa_secret.

    Returns: False if the verification failed, otherwise a set of recovery codes
    generated from tfa_generate_recovery_codes().
    """
    totp = pyotp.TOTP(tfa_secret)
    # If the provided `tfa_response` matches the TOTP value, add the value and return recovery codes
    if totp.verify(tfa_response):
        d.engine.execute("""
            UPDATE login
            SET twofa_secret = (%(tfa_secret)s)
            WHERE userid = (%(userid)s)
        """)
        return generate_recovery_codes(userid)
    else:
        return False


def verify(userid, tfa_response):
    """
    Verify a 2FA-enabled user's 2FA challenge-response against the stored
    2FA secret.

    Parameters:
        userid: The userid to compare the 2FA challenge-response against.
        tfa_response: User-supplied response. May be either the Google Authenticator
        (or other app) supplied code, or a recovery code

    Returns: Boolean True if 2FA verification is successful, Boolean False otherwise.
    """
    tfa_secret = d.engine.scalar("""
        SELECT twofa_secret
        FROM login
        WHERE userid = (%(userid)s)
    """, userid=userid)
    # Validate supplied 2FA response versus calculated current TOTP value.
    totp = pytop.TOTP(tfa_secret)
    if totp.verify(tfa_response):
        return True
    # TOTP verification failed, check recovery code
    else:
        if is_recovery_code_valid(userid, tfa_response):
            # Recovery code was valid, and consumed
            return True
        else:
            # Received input was not a valid TOTP response, and was not a valid recovery code
            return False


def generate_recovery_codes(userid):
    """
    Generate a fresh set of 2FA recovery codes for a user.

    Initializes or otherwise refreshes the 2FA recovery codes for a user,
    by deleting all rows from the recovery table where the userid matches the
    supplied userid, and generates fresh codes to supply to the user.

    Parameters:
        userid: The userid to create new recovery codes for.

    Returns:
        A set of recovery codes linked to the passed userid.
    """
    # First, purge existing recovery codes (if any).
    d.engine.execute("""
        DELETE FROM recovery_codes
        WHERE userid = (%(userid)s);
    """, userid=userid)
    # Next, generate the recovery codes, up to the defined maximum value
    for i in range(0, _TFA_RECOVERY_CODES):
        tfa_recovery_codes |= {security.generate_key(20)}
    # Then, insert the codes into the table
    ## TODO: Figure out how to do this in one shot instead of looping the codes; this feels inelegant.
    #for code in tfa_recovery_codes:
        #d.engine.execute("""
        #    INSERT INTO twofa_recovery_codes (userid, recovery_code)
        #    VALUES ( (%(userid)s), (%(code)s) )
        #""", userid=userid, code=code)
    d.engine.execute("""
        INSERT INTO twofa_recovery_codes (userid, recovery_code)
        SELECT (%(userid)s), unnest( (%(tfa_recovery_codes)s) )
    """, userid=userid, tfa_recovery_codes=list(tfa_recovery_codes))
    # Finally, return the set of recovery codes to the calling function.
    return tfa_recovery_codes



def is_recovery_code_valid(userid, tfa_code):
    """
    Checks the recovery code table for a valid recovery code.

    Determine if a supplied recovery code is present in the recovery code table
    for a specified userid. If present, consume the code by deleting the record.

    Parameters:
        userid: The userid of the requesting user.
        tfa_code: A candidate recovery code to check.

    Returns: Boolean True if the code was valid and has been consumed, Boolean False, otherwise.
    """
    # Check to see if the provided code is valid, and consume if so
    tfa_rc = d.engine.scalar("""
        DELETE FROM recovery_codes
        WHERE userid = (%(userid)s), recovery_code = (%(recovery_code)s)
        RETURNING recovery_code
    """, userid=userid, recovery_code=tfa_code)
    # If `tfa_rc` is not None, the code was valid and consumed.
    if tfa_rc:
        return True
    else:
        return False


def deactivate(userid):
    """
    Deactivate 2FA for a specified user.

    Turns off 2FA by nulling-out the ``login.twofa_secret`` field for the user record,
    and clear any remaining recovery codes.

    Parameters:
        userid: The user for which 2FA should be disabled.

    Returns: Nothing.
    """
    # Atomically disable 2FA to prevent either step from failing and resulting in a (potentially) inconsistent state.
    d.engine.execute("""
        BEGIN;
        
        UPDATE login
        SET twofa_secret = NULL
        WHERE userid = (%(userid)s);
        
        DELETE FROM recovery_codes
        WHERE userid = (%(userid)s);
        
        COMMIT;
    """, userid=userid)
