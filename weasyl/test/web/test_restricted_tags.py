from __future__ import absolute_import, unicode_literals

import pytest

from libweasyl import staff
from weasyl import define
from weasyl import errorcode
from weasyl import searchtag
from weasyl.test import db_utils
from weasyl.test.web.wsgi import app


tag_global = "global_restricted_tag_xyzzy"
tag_user = "user_restricted_tag_xyzzy"


@pytest.fixture(name='restricted_tags')
@pytest.mark.usefixtures('db')
def _restricted_tags(monkeypatch):
    # Create a normal user
    user = db_utils.create_user(username='testuser')
    searchtag.edit_user_tag_restrictions(user, {tag_user})

    # Create a director
    director = db_utils.create_user(username='testdirector')
    monkeypatch.setattr(staff, 'DIRECTORS', frozenset([director]))
    monkeypatch.setattr(staff, 'TECHNICAL', frozenset([director]))
    monkeypatch.setattr(staff, 'ADMINS', frozenset([director]))
    monkeypatch.setattr(staff, 'MODS', frozenset([director]))
    searchtag.edit_global_tag_restrictions(director, {tag_global})

    # Create sessions for the user/director
    user_cookie = db_utils.create_session(user)
    director_cookie = db_utils.create_session(director)

    return (user, user_cookie, director, director_cookie)


@pytest.fixture(name='no_view_increment')
def _no_view_increment(monkeypatch):
    def common_view_content(userid, targetid, feature):
        return True

    monkeypatch.setattr(define, 'common_view_content', common_view_content)


@pytest.mark.usefixtures('db')
def test_view_empty_user_and_global_restricted_tags_page(monkeypatch):
    # User restricted tags, logged out user (fails, login required)
    resp = app.get('/control/tagrestrictions')
    assert resp.html.find(id='error_content').contents[0].strip() == errorcode.unsigned
    # Globally restricted tags, logged out user (fails, director login required)
    resp = app.get('/directorcontrol/globaltagrestrictions')
    assert resp.html.find(id='error_content').contents[0].strip() == errorcode.unsigned

    # User restricted tags, logged in user (succeeds, empty list)
    user = db_utils.create_user()
    user_cookie = db_utils.create_session(user)
    resp = app.get('/control/tagrestrictions', headers={'Cookie': user_cookie})
    with pytest.raises(IndexError) as err:
        resp.html.find(id="tags-textarea").contents[0].strip()
    assert err.match(r"list index out of range")

    # Globally restricted tags, logged in director (succeeds, empty list)
    director = db_utils.create_user()
    monkeypatch.setattr(staff, 'DIRECTORS', frozenset([director]))
    director_cookie = db_utils.create_session(director)
    resp = app.get('/directorcontrol/globaltagrestrictions', headers={'Cookie': director_cookie})
    assert "No community tags are currently restricted." in resp


@pytest.mark.usefixtures('db')
def test_ensure_non_directors_cannot_access_global_restricted_tags(monkeypatch):
    user = db_utils.create_user()
    user_cookie = db_utils.create_session(user)
    resp = app.get('/directorcontrol/globaltagrestrictions', headers={'Cookie': user_cookie})
    assert resp.html.find(id='error_content').p.string == errorcode.permission

    monkeypatch.setattr(staff, 'DEVELOPERS', frozenset([user]))
    resp = app.get('/directorcontrol/globaltagrestrictions', headers={'Cookie': user_cookie})
    assert resp.html.find(id='error_content').p.string == errorcode.permission

    monkeypatch.setattr(staff, 'MODS', frozenset([user]))
    resp = app.get('/directorcontrol/globaltagrestrictions', headers={'Cookie': user_cookie})
    assert resp.html.find(id='error_content').p.string == errorcode.permission

    monkeypatch.setattr(staff, 'TECHNICAL', frozenset([user]))
    resp = app.get('/directorcontrol/globaltagrestrictions', headers={'Cookie': user_cookie})
    assert resp.html.find(id='error_content').p.string == errorcode.permission

    monkeypatch.setattr(staff, 'ADMINS', frozenset([user]))
    resp = app.get('/directorcontrol/globaltagrestrictions', headers={'Cookie': user_cookie})
    assert resp.html.find(id='error_content').p.string == errorcode.permission


@pytest.mark.usefixtures('db')
def test_view_inuse_user_and_global_restricted_tags_page(restricted_tags):
    _, user_cookie, _, director_cookie = restricted_tags

    resp = app.get('/control/tagrestrictions', headers={'Cookie': user_cookie})
    assert resp.html.find(id='tags-textarea').contents[0].strip() == tag_user

    resp = app.get('/directorcontrol/globaltagrestrictions', headers={'Cookie': director_cookie})
    assert resp.html.find(id='tags-textarea').contents[0].strip() == tag_global


@pytest.mark.usefixtures('db')
def test_verify_that_csrf_check_exists_on_user_and_global_restricted_tags(restricted_tags):
    _, user_cookie, _, director_cookie = restricted_tags

    # User and Global restricted tags POST routes require CSRF; verify this exists and functions
    resp = app.post('/control/tagrestrictions', {'tags': tag_user}, headers={'Cookie': user_cookie})
    assert resp.html.find(id='error_content').p.string == errorcode.token
    resp = app.post('/directorcontrol/globaltagrestrictions', {'tags': tag_global}, headers={'Cookie': director_cookie})
    assert resp.html.find(id='error_content').p.string == errorcode.token


@pytest.mark.usefixtures('db', 'no_csrf')
def test_adding_user_and_global_restricted_tags(restricted_tags):
    user, user_cookie, director, director_cookie = restricted_tags

    # Clear restricted tags
    searchtag.edit_user_tag_restrictions(user, set())
    searchtag.edit_user_tag_restrictions(director, set())

    # Set the tags and verify that they were set correctly
    resp = app.post('/control/tagrestrictions', {'tags': 'user_restricted_tag_xyzzy2'}, headers={'Cookie': user_cookie})
    assert resp.html.find(id='tags-textarea').contents[0].strip() == "user_restricted_tag_xyzzy2"
    resp = app.post('/directorcontrol/globaltagrestrictions', {'tags': 'global_restricted_tag_xyzzy2'}, headers={'Cookie': director_cookie})
    assert resp.html.find(id='tags-textarea').contents[0].strip() == "global_restricted_tag_xyzzy2"
    assert resp.html.find("form", class_="form skinny clear").table.tbody.tr.td.string == "testdirector"


@pytest.mark.usefixtures('db', 'no_csrf')
def test_attempt_adding_restricted_tags_to_submissions(restricted_tags, no_view_increment):
    userid_owner, owner_cookie, _, director_cookie = restricted_tags
    userid_tag_adder = db_utils.create_user()
    tag_adder_cookie = db_utils.create_session(userid_tag_adder)

    # Content items can be reused between tested functions
    submission = db_utils.create_submission(userid_owner)
    character = db_utils.create_character(userid_owner)
    journal = db_utils.create_journal(userid_owner)
    """ Other users tests"""
    # Other users cannot add tags which have been user-restricted
    resp = app.post('/submit/tags', {'submitid': submission, 'tags': tag_user}, headers={'Cookie': tag_adder_cookie}).follow()
    assert tag_user not in resp.html.find(id='tags-textarea')
    resp = app.post('/submit/tags', {'charid': character, 'tags': tag_user}, headers={'Cookie': tag_adder_cookie}).follow()
    assert tag_user not in resp.html.find(id='tags-textarea')
    resp = app.post('/submit/tags', {'journalid': journal, 'tags': tag_user}, headers={'Cookie': tag_adder_cookie}).follow()
    assert tag_user not in resp.html.find(id='tags-textarea')

    # Other users cannot add tags which have been globally restricted
    resp = app.post('/submit/tags', {'submitid': submission, 'tags': tag_global}, headers={'Cookie': tag_adder_cookie}).follow()
    assert tag_global not in resp.html.find(id='tags-textarea')
    resp = app.post('/submit/tags', {'charid': character, 'tags': tag_global}, headers={'Cookie': tag_adder_cookie}).follow()
    assert tag_global not in resp.html.find(id='tags-textarea')
    resp = app.post('/submit/tags', {'journalid': journal, 'tags': tag_global}, headers={'Cookie': tag_adder_cookie}).follow()
    assert tag_global not in resp.html.find(id='tags-textarea')

    """ Content owner tests """
    # Content owners can add tags which are user-restricted
    resp = app.post('/submit/tags', {'submitid': submission, 'tags': tag_user}, headers={'Cookie': owner_cookie}).follow()
    assert resp.html.find(id='tags-textarea').string == tag_user
    resp = app.post('/submit/tags', {'charid': character, 'tags': tag_user}, headers={'Cookie': owner_cookie}).follow()
    assert resp.html.find(id='tags-textarea').string == tag_user
    resp = app.post('/submit/tags', {'journalid': journal, 'tags': tag_user}, headers={'Cookie': owner_cookie}).follow()
    assert resp.html.find(id='tags-textarea').string == tag_user

    # Content owners can add tags which are globally restricted
    resp = app.post('/submit/tags', {'submitid': submission, 'tags': tag_global}, headers={'Cookie': owner_cookie}).follow()
    assert resp.html.find(id='tags-textarea').string == tag_global
    resp = app.post('/submit/tags', {'charid': character, 'tags': tag_global}, headers={'Cookie': owner_cookie}).follow()
    assert resp.html.find(id='tags-textarea').string == tag_global
    resp = app.post('/submit/tags', {'journalid': journal, 'tags': tag_global}, headers={'Cookie': owner_cookie}).follow()
    assert resp.html.find(id='tags-textarea').string == tag_global

    """ Moderators (or above) tests) """
    # Moderators (or above) can add tags which are user-restricted
    resp = app.post('/submit/tags', {'submitid': submission, 'tags': tag_user}, headers={'Cookie': director_cookie}).follow()
    assert resp.html.find(id='tags-textarea').string == tag_user
    resp = app.post('/submit/tags', {'charid': character, 'tags': tag_user}, headers={'Cookie': director_cookie}).follow()
    assert resp.html.find(id='tags-textarea').string == tag_user
    resp = app.post('/submit/tags', {'journalid': journal, 'tags': tag_user}, headers={'Cookie': director_cookie}).follow()
    assert resp.html.find(id='tags-textarea').string == tag_user

    # Moderators (or above) can add tags which are globally restricted
    resp = app.post('/submit/tags', {'submitid': submission, 'tags': tag_global}, headers={'Cookie': director_cookie}).follow()
    assert resp.html.find(id='tags-textarea').string == tag_global
    resp = app.post('/submit/tags', {'charid': character, 'tags': tag_global}, headers={'Cookie': director_cookie}).follow()
    assert resp.html.find(id='tags-textarea').string == tag_global
    resp = app.post('/submit/tags', {'journalid': journal, 'tags': tag_global}, headers={'Cookie': director_cookie}).follow()
    assert resp.html.find(id='tags-textarea').string == tag_global
