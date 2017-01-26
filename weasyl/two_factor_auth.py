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
    tfa_qrcode = base64.b64encode(qrcode.make(totp_uri))
    # Return the tuple
    return tfa_secret, tfa_qrcode


def init_verify_tfa(userid, tfa_secret, tfa_response):
    """
    Verify that the user has successfully set-up 2FA in Google Authenticator
    (or similar), and generate recovery codes for the user.

    This function is part one of two in enabling 2FA. Successful verification of this phase
    ensures that the user's authentication app is working correctly.

    Parameters:
        userid: The userid of the calling user.
        tfa_secret: The 2FA secret generated from tfa_init(); retrieved from the
        verification page's form information.
        tfa_response: The 2FA challenge-response code to verify against tfa_secret.

    Returns:
        - Boolean False if the verification failed; or
        - A tuple in the form of (tfa_secret, generate_recovery_codes(userid)) where:
            tfa_secret: Is the verified working TOTP secret key
            generate_recovery_codes(userid): Is a list of recovery codes bound to the user.
    """
    totp = pyotp.TOTP(tfa_secret)
    # If the provided `tfa_response` matches the TOTP value, add the value and return recovery codes
    if totp.verify(tfa_response):
        return tfa_secret, generate_recovery_codes(userid)
    else:
        return False


def activate(userid, tfa_secret, tfa_response):
    """
    Fully activate 2FA for a given user account, after final validation of the TOTP secret.

    This function is part two--the final part--in enabling 2FA. Passing this step ensures that
    the user has been presented the opportunity to save recovery keys for their account.

    Parameters:
        userid: The userid of the calling user.
        tfa_secret: The 2FA secret generated from tfa_init(); retrieved from the
        verification page's form information.
        tfa_response: The 2FA challenge-response code to verify against tfa_secret.

    Returns: Boolean True if the `tfa_response` corresponds with `tfa_secret`, thus enabling 2FA,
        otherwise Boolean False indicating 2FA has not been enabled.
    """
    totp = pyotp.TOTP(tfa_secret)
    # If the provided `tfa_response` matches the TOTP value, write the 2FA secret into `login`, activating 2FA for `userid`
    if totp.verify(tfa_response):
        d.engine.execute("""
            UPDATE login
            SET twofa_secret = (%(tfa_secret)s)
            WHERE userid = (%(userid)s)
        """)
        return True
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


def get_number_of_recovery_codes(userid):
    """
    Get and return the number of remaining recovery codes for `userid`.
    
    Parameters:
        userid: The userid for which to check the count of recovery codes.

    Returns:
        An integer representing the number of remaining recovery codes.
    """
    return d.engine.scalar("""
        SELECT COUNT(*)
        FROM twofa_recovery_codes
        WHERE userid = (%(userid)s)
    """, userid=userid)


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
        DELETE FROM twofa_recovery_codes
        WHERE userid = (%(userid)s);
    """, userid=userid)
    # Next, generate the recovery codes, up to the defined maximum value
    tfa_recovery_codes = {security.generate_key(20)}
    for i in range(0, _TFA_RECOVERY_CODES - 1):
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
        DELETE FROM twofa_recovery_codes
        WHERE userid = (%(userid)s), recovery_code = (%(recovery_code)s)
        RETURNING recovery_code
    """, userid=userid, recovery_code=tfa_code)
    # If `tfa_rc` is not None, the code was valid and consumed.
    if tfa_rc:
        return True
    else:
        return False


def deactivate(userid, tfa_response):
    """
    Deactivate 2FA for a specified user.

    Turns off 2FA by nulling-out the ``login.twofa_secret`` field for the user record,
    and clear any remaining recovery codes.

    Parameters:
        userid: The user for which 2FA should be disabled.
        tfa_response: User-supplied response. May be either the Google Authenticator
        (or other app) supplied code, or a recovery code.

    Returns: Boolean True if 2FA was successfully disabled, otherwise Boolean False if the
    verification of `tfa_response` failed (bad challenge-response or invalid recovery code).
    """
    if verify(userid, tfa_response):
        # Atomically disable 2FA to prevent either step from failing and resulting in a (potentially) inconsistent state.
        d.engine.execute("""
            BEGIN;

            UPDATE login
            SET twofa_secret = NULL
            WHERE userid = (%(userid)s);

            DELETE FROM twofa_recovery_codes
            WHERE userid = (%(userid)s);

            COMMIT;
        """, userid=userid)
        return True
    else:
        return False
