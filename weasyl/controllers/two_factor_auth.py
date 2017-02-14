from __future__ import absolute_import, unicode_literals

from pyramid.response import Response

from weasyl import define
from weasyl import login
from weasyl import two_factor_auth as tfa
from weasyl.controllers.decorators import (
    login_required,
    token_checked,
)


@login_required
def tfa_status_get_(request):
    return Response(define.webpage(request.userid, "control/2fa/status.html",
                    [tfa.is_2fa_enabled(request.userid), tfa.get_number_of_recovery_codes(request.userid)]))


@login_required
def tfa_init_get_(request):
    if tfa.is_2fa_enabled(request.userid):
        return Response(define.errorpage(
            request.userid,
            "2FA is already configured for this account.",
            [["Go Back", "/control"], ["Return to the Home Page", "/"]]))
    else:
        username = define.engine.scalar("""
            SELECT login_name
            FROM login
            WHERE userid = (%(userid)s)
        """, userid=request.userid)
        tfa_secret, tfa_qrcode = tfa.init(request.userid)
        return Response(define.webpage(request.userid, "control/2fa/init.html",
                        [username, tfa_secret, tfa_qrcode, None]))


@login_required
@token_checked
def tfa_init_post_(request):
    if tfa.is_2fa_enabled(request.userid):
        return Response(define.errorpage(
            request.userid,
            "2FA is already configured for this account.",
            [["Go Back", "/control"], ["Return to the Home Page", "/"]]))
    
    userid, status = login.authenticate_bcrypt(d.get_display_name(request.userid),
                                               request.params['password'], session=False)

    # The user's password failed to authenticate
    if status == "invalid":
        return Response(define.webpage(request.userid, "control/2fa/init.html",
            [username, request.params['tfasecret'],
             tfa.generate_tfa_qrcode(request.userid, request.params['tfasecret']), "password"]))
    tfa_secret, recovery_codes = tfa.init_verify_tfa(request.userid, tfa_secret, request.params['tfaresponse'])

    # The 2FA TOTP code did not match with the generated 2FA secret
    if not tfa_secret:
        return Response(define.webpage(request.userid, "control/2fa/init.html",
            [username, request.params['tfasecret'],
             tfa.generate_tfa_qrcode(request.userid, request.params['tfasecret']), "2fa"]))
    else:
        return Response(define.webpage(request.userid, "control/2fa/init_verify.html",
            [tfa_secret, recovery_codes, None]))


@login_required
def tfa_init_verify_get_(request):
    pass


@login_required
@token_checked
def tfa_init_verify_post_(request):
    pass