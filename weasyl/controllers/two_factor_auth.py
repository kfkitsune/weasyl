from __future__ import absolute_import, unicode_literals

from pyramid.response import Response

from weasyl import define
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
def tfa_init_post_(request):
    pass
