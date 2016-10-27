from __future__ import absolute_import, unicode_literals

import pytest

from weasyl import profile, searchtag
from weasyl.error import WeasylError
from weasyl.test import db_utils

# Tag set for testing
tags = ['apple', 'orange']


@pytest.mark.usefixtures('db')
def test_TargetRecordMissing_WeasylError_if_item_record_missing_or_invalid():
    userid_tag_adder = db_utils.create_user()
    
    with pytest.raises(WeasylError) as err:
        searchtag.associate(userid_tag_adder, tags, submitid=666)
    assert err.value.value == "TargetRecordMissing"
    
    with pytest.raises(WeasylError) as err:
        searchtag.associate(userid_tag_adder, tags, charid=666)
    assert err.value.value == "TargetRecordMissing"
    
    with pytest.raises(WeasylError) as err:
        searchtag.associate(userid_tag_adder, tags, journalid=666)
    assert err.value.value == "TargetRecordMissing"


@pytest.mark.usefixtures('db')
def test_InsufficientPermissions_WeasylError_if_user_does_not_have_tagging_permissions():
    # Set up for this test
    admin = db_utils.create_user()
    userid_owner = db_utils.create_user()
    userid_tag_adder = db_utils.create_user()
    journalid = db_utils.create_journal(userid_owner)
    charid = db_utils.create_character(userid_owner)
    submitid = db_utils.create_submission(userid_owner)
    profile.do_manage(admin, userid_owner, permission_tag=False)
    
    with pytest.raises(WeasylError) as err:
        searchtag.associate(userid_tag_adder, tags, submitid=submitid)
    assert err.value.value == "InsufficientPermissions"
    
    with pytest.raises(WeasylError) as err:
        searchtag.associate(userid_tag_adder, tags, charid=charid)
    assert err.value.value == "InsufficientPermissions"
    
    with pytest.raises(WeasylError) as err:
        searchtag.associate(userid_tag_adder, tags, journalid=journalid)
    assert err.value.value == "InsufficientPermissions"


@pytest.mark.usefixtures('db')
def test_contentOwnerIgnoredYou_WeasylError_if_user_ignored_by_item_owner():
    # Set up for this test
    userid_owner = db_utils.create_user()
    userid_tag_adder = db_utils.create_user()
    journalid = db_utils.create_journal(userid_owner)
    charid = db_utils.create_character(userid_owner)
    submitid = db_utils.create_submission(userid_owner)
    db_utils.create_ignoreuser(userid_owner, userid_tag_adder)
    
    with pytest.raises(WeasylError) as err:
        searchtag.associate(userid_tag_adder, tags, submitid=submitid)
    assert err.value.value == "contentOwnerIgnoredYou"
    
    with pytest.raises(WeasylError) as err:
        searchtag.associate(userid_tag_adder, tags, charid=charid)
    assert err.value.value == "contentOwnerIgnoredYou"
    
    with pytest.raises(WeasylError) as err:
        searchtag.associate(userid_tag_adder, tags, journalid=journalid)
    assert err.value.value == "contentOwnerIgnoredYou"








