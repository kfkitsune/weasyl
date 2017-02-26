from __future__ import absolute_import, unicode_literals

from pyramid.response import Response
from pyramid.httpexceptions import HTTPSeeOther

from weasyl import define
from weasyl import login
from weasyl import two_factor_auth as tfa
from weasyl.controllers.decorators import (
    login_required,
    token_checked,
)
from weasyl.error import WeasylError


def _error_if_2fa_enabled(userid):
    """
    In lieu of a module-specific decorator, this function returns an error if 2FA is enabled, preventing the user
    from self-wiping their own 2FA Secret (AKA, re-setting up 2FA while it is already enabled)
    """
    if tfa.is_2fa_enabled(userid):
        return Response(define.errorpage(userid, "2FA is already configured for this account.", [
            ["Go Back", "/control"], ["Return to the Home Page", "/"]
        ]))


def _error_if_2fa_is_not_enabled(userid):
    """
    In lieu of a module-specific decorator, this function returns an error if 2FA is not enabled.
    """
    if not tfa.is_2fa_enabled(userid):
        return Response(define.errorpage(userid, "2FA is not configured for this account.", [
            ["Go Back", "/control"], ["Return to the Home Page", "/"]
        ]))


@login_required
def tfa_status_get_(request):
    return Response(define.webpage(request.userid, "control/2fa/status.html", [
        tfa.is_2fa_enabled(request.userid), tfa.get_number_of_recovery_codes(request.userid)
    ]))


@login_required
def tfa_init_get_(request):
    # Return an error if 2FA is already enabled (there's nothing to do in this route)
    _error_if_2fa_enabled(request.userid)

    # Otherwise begin the 2FA initialization process for this user
    tfa_secret, tfa_qrcode = tfa.init(request.userid)
    return Response(define.webpage(request.userid, "control/2fa/init.html",
                    [define.get_display_name(request.userid), tfa_secret, tfa_qrcode, None]))


@login_required
@token_checked
def tfa_init_post_(request):
    # Return an error if 2FA is already enabled (there's nothing to do in this route)
    _error_if_2fa_enabled(request.userid)

    # Otherwise, process the form
    if request.params['action'] == "cancel":
        raise HTTPSeeOther(location="/control")
    elif request.params['action'] == "continue":
        userid, status = login.authenticate_bcrypt(define.get_display_name(request.userid),
                                                   request.params['password'], session=False)
        # The user's password failed to authenticate
        if status == "invalid":
            return Response(define.webpage(request.userid, "control/2fa/init.html", [
                define.get_display_name(request.userid),
                request.params['tfasecret'],
                tfa.generate_tfa_qrcode(request.userid, request.params['tfasecret']),
                "password"
            ]))
        # Unlikely that this block will get triggered, but just to be safe, check for it
        elif status == "unicode-failure":
            raise HTTPSeeOther(location='/signin/unicode-failure')
        tfa_secret, recovery_codes = tfa.init_verify_tfa(request.userid, request.params['tfasecret'], request.params['tfaresponse'])

        # The 2FA TOTP code did not match with the generated 2FA secret
        if not tfa_secret:
            return Response(define.webpage(request.userid, "control/2fa/init.html", [
                define.get_display_name(request.userid),
                request.params['tfasecret'],
                tfa.generate_tfa_qrcode(request.userid, request.params['tfasecret']),
                "2fa"
            ]))
        else:
            return Response(define.webpage(request.userid, "control/2fa/init_verify.html",
                            [tfa_secret, recovery_codes, None]))
    else:
        # This shouldn't be reached normally (user intentionally altered action?)
        raise WeasylError("Unexpected")


@login_required
def tfa_init_verify_get_(request):
    """
    IMPLEMENTATION NOTE: This page cannot be accessed directly (HTTP GET), as the user has not generated
    their 2FA secret at this point, and thus not loaded the secret into their 2FA authenticator of choice.
    That said, be helpful and inform the user of this instead of erroring without explanation.
    """
    # Return an error if 2FA is already enabled (there's nothing to do in this route)
    _error_if_2fa_enabled(request.userid)

    # If 2FA is not enabled, inform the user of where to go to begin
    return Response(define.errorpage(
                    request.userid,
                    """This page cannot be accessed directly, and must be accessed as part of the 2FA
                    setup process. Click <b>2FA Status</b>, below, to go to the 2FA Dashboard to begin.""",
                    [["2FA Status", "/control/2fa/status"], ["Return to the Home Page", "/"]]))


@login_required
@token_checked
def tfa_init_verify_post_(request):
    # Return an error if 2FA is already enabled (there's nothing to do in this route)
    _error_if_2fa_enabled(request.userid)

    # Extract parameters from the form
    action = request.params['action']
    verify_checkbox = request.params['verify']
    tfasecret = request.params['tfasecret']
    tfaresponse = request.params['tfaresponse']
    tfarecoverycodes = request.params['tfarecoverycodes']

    # Does the user want to proceed with enabling 2FA?
    if action == "enable" and verify_checkbox and tfa.store_recovery_codes(request.userid, tfarecoverycodes):
        # TOTP+2FA Secret validates (activate & redirect to status page)
        if tfa.activate(request.userid, tfasecret, tfaresponse):
            raise HTTPSeeOther(location="/control/2fa/status")
        # TOTP+2FA Secret did not validate
        else:
            return Response(define.webpage(request.userid, "control/2fa/init_verify.html",
                            [tfasecret, tfarecoverycodes.split(','), "2fa"]))

    # The user didn't check the verification checkbox (despite HTML5's client-side check); regenerate codes & redisplay
    elif action == "enable" and not verify_checkbox:
        return Response(define.webpage(request.userid, "control/2fa/init_verify.html",
                        [tfasecret, tfarecoverycodes.split(','), "verify"]))

    # User wishes to cancel, so bail out
    elif action == "cancel":
        raise HTTPSeeOther(location="/control/2fa/status")
    else:
        # This shouldn't be reached normally (user intentionally altered action?)
        raise WeasylError("Unexpected")


@login_required
def tfa_disable_get_(request):
    # Return an error if 2FA is not enabled (there's nothing to do in this route)
    _error_if_2fa_is_not_enabled(request.userid)

    return Response(define.webpage(request.userid, "control/2fa/disable.html",
                    [define.get_display_name(request.userid), None]))


@login_required
@token_checked
def tfa_disable_post_(request):
    # Return an error if 2FA is not enabled (there's nothing to do in this route)
    _error_if_2fa_is_not_enabled(request.userid)

    tfaresponse = request.params['tfaresponse']
    verify_checkbox = request.params['verify']
    action = request.params['action']

    if action == "disable" and verify_checkbox:
        # If 2FA was successfully deactivated... return to 2FA dashboard
        if tfa.deactivate(request.userid, tfaresponse):
            raise HTTPSeeOther(location="/control/2fa/status")
        else:
            return Response(define.webpage(request.userid, "control/2fa/disable.html",
                            [define.get_display_name(request.userid), "2fa"]))
    # The user didn't check the verification checkbox (despite HTML5's client-side check)
    elif action == "disable" and not verify_checkbox:
        return Response(define.webpage(request.userid, "control/2fa/disable.html",
                        [define.get_display_name(request.userid), "verify"]))
    # User wishes to cancel, so bail out
    elif action == "cancel":
        raise HTTPSeeOther(location="/control/2fa/status")
    else:
        # This shouldn't be reached normally (user intentionally altered action?)
        raise WeasylError("Unexpected")


"""
@login_required
def tfa_gen_recovery_codes_get_(request):
    # Return an error if 2FA is not enabled (there's nothing to do in this route)
    _error_if_2fa_is_not_enabled(request.userid)

    pass


@login_required
@token_checked
def tfa_gen_recovery_codes_post_(request):
    # Return an error if 2FA is not enabled (there's nothing to do in this route)
    _error_if_2fa_is_not_enabled(request.userid)

    pass
"""
