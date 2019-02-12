#!/usr/bin/env python3

import requests
import json
import logging

logger = logging.getLogger(__name__)


class Ipa(object):

    def __init__(self, server, ssl_verify=True):
        self._server = server
        self._ssl_verify = ssl_verify
        self._session = requests.Session()

    def login(self, username: str, password: str):
        ipa_url = 'https://{0}/ipa/session/login_password'.format(self._server)
        headers = {
            'Referer': ipa_url,
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'text/plain'
        }
        payload = {'user': username, 'password': password}
        r = self._session.post(ipa_url, headers=headers, data=payload, verify=self._ssl_verify)
        
        if r.status_code != 200:
            logger.warning('Login failed for user {0} on {1}'.format(username, self._server))
        else:
            logger.info('Successfully logged in as {0} on {1}'.format(username, self._server))
        return r

    def make_req(self, method: str, *args, **kwargs) -> dict:
        ipa_url = 'https://{0}/ipa'.format(self._server)
        session_url = '{0}/session/json'.format(ipa_url)
        headers = {
            'Referer': ipa_url,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        payload = {'method': method, 'params': [args, kwargs]}
        
        logger.debug('Making {0} request to {1}'.format(payload, session_url))
        
        request = self._session.post(session_url, headers=headers, data=json.dumps(payload), verify=self._ssl_verify)
        result = request.json()
        return result if result['error'] else result['result']

    def config_show(self):
        return self.make_req('config_show')

    def user_add(self, firstname, lastname, uid, **kwargs):
        return self.make_req('user_add', uid, givenname=firstname, sn=lastname, **kwargs)

    def user_del(self, uid):
        return self.make_req('user_del', uid)

    def user_disable(self, uid):
        return self.make_req('user_disable', uid)

    def user_enable(self, uid):
        return self.make_req('user_enable', uid)

    def user_show(self, uid):
        return self.make_req('user_show', uid)

    def user_mod(self, uid, **kwargs):
        return self.make_req('user_mod', uid, **kwargs)

    def user_find(self, criteria="", **kwargs):
        return self.make_req('user_find', criteria, **kwargs)

    def group_add(self, gid, **kwargs):
        return self.make_req('group_add', gid, **kwargs)

    def group_del(self, gid):
        return self.make_req('group_del', gid)

    def group_add_member(self, gid, **kwargs):
        return self.make_req('group_add_member', gid, **kwargs)

    def group_remove_member(self, gid, **kwargs):
        return self.make_req('group_remove_member', gid, **kwargs)

    def group_show(self, gid):
        return self.make_req('group_show', gid)

    def group_mod(self, gid, **kwargs):
        return self.make_req('group_mod', gid, **kwargs)

    def group_find(self, criteria="", **kwargs):
        return self.make_req('group_find', criteria, **kwargs)
