"""
Module for handling 2FA-related functions.
"""
from __future__ import absolute_import

import arrow
import qrcode
import pyotp

from weasyl import define as d


def tfa_init(userid):
    """
    Initialize 2FA for a user by generating and returning a 2FA secret key.

    When a user opts-in to 2FA, this function generates the necessary 2FA secret,
    and QRcode.

    Parameters:
        userid: The userid of the calling user.

    Returns:
        tfa_secret: The 16 character pyotp-generated secret.
        tfa_qrcode: Base64-encoded QRcode containing necessary information for
        Google Authenticator use.
    """
    pass


def tfa_init_verify(userid, tfa_secret, tfa_response):
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

    Returns: False if the verification failed, otherwise a list of recovery codes
    generated from tfa_generate_recovery_codes().
    """
    pass


def tfa_verify(userid, tfa_response):
    """
    Verify a 2FA-enabled user's 2FA challenge-response against the stored
    2FA secret.

    Parameters:
        userid: The userid to compare the 2FA challenge-response against.
        tfa_response: User-supplied response. May be either the Google Authenticator
        (or other app) supplied code, or a recovery code
    """
    pass


def tfa_generate_recovery_codes(userid):
    """
    Generate a fresh set of 2FA recovery codes for a user.

    Initializes or otherwise refreshes the 2FA recovery codes for a user,
    by deleting all rows from the recovery table where the userid matches the
    supplied userid, and generates fresh codes to supply to the user.

    Parameters:
        userid: The userid to create new recovery codes for.

    Returns:
        A list of recovery codes linked to the passed userid.
    """
    pass


def tfa_is_recovery_code_valid(userid, tfa_code):
    """
    Checks the recovery code table for a valid recovery code.

    Determine if a supplied recovery code is present in the recovery code table
    for a specified userid. If present, consume the code by deleting the record.

    Parameters:
        userid: The userid of the requesting user.
        tfa_code: A candidate recovery code to check.

    Returns: Boolean True if the code was valid and has been consumed, Boolean False, otherwise.
    """
    pass


def tfa_deactivate(userid):
    """
    Deactivate 2FA for a specified user.

    Turns off 2FA by nulling-out the ``login.twofa_secret`` field for the user record,
    and clear any remaining recovery codes.

    Parameters:
        userid: The user for which 2FA should be disabled.

    Returns: Nothing.
    """
    pass
