#!/usr/bin/env python
#
# Copyright (c) 2018 YADRO
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
""" Helper to send REST requests to the BMC. """

import argparse
import json
import os
import requests

try:
    import configparser
except ImportError:
    import ConfigParser as configparser

from xdg.BaseDirectory import xdg_config_home


class BMC:
    """ BMC seesion """
    def __init__(self, server, username, password):
        self.url = "https://{0}".format(server)
        self.session = requests.Session()
        self.login(username, password)

    def login(self, username, password):
        """ Send a login request. """
        req = self.session.post(self.url + '/login',
                                json={'data': [username, password]},
                                verify=False)
        jdata = req.json()
        if jdata['status'] != 'ok':
            raise Exception("Failed to login: \n" + req.text)

        if 'SESSION' in self.session.cookies:
            self.session.headers.update({
                'X-Auth-Token': self.session.cookies['SESSION']
                })

    def list(self, path):
        """ Send a list request. """
        req = self.session.get(self.url + path + '/list',
                               verify=False)
        jdata = req.json()
        if jdata['status'] != 'ok':
            raise Exception("Failed to query list: \n" + req.text)

        return jdata['data']

    def enum(self, path):
        """ Send a enumerate request. """
        req = self.session.get(self.url + path + '/enumerate',
                               verify=False)
        jdata = req.json()
        if jdata['status'] != 'ok':
            raise Exception("Failed to query enumerate: \n" + req.text)

        return jdata['data']

    def get(self, path):
        """ Send a simple get request. """
        req = self.session.get(self.url + path, verify=False)

        jdata = req.json()
        if jdata['status'] != 'ok':
            raise Exception("Failed to query get: \n" + req.text)

        return jdata['data']

    def put(self, path, value):
        """ Send a put request. """
        req = self.session.put(self.url + path,
                               json={'data': value},
                               verify=False)
        jdata = req.json()
        if jdata['status'] != 'ok':
            raise Exception("Failed to qeury put: \n" + req.text)

        return True

def _get_cfg_value(cfg, server, option):
    """ Get actual value of option from config. """
    value = None
    if cfg.has_option(server, option):
        value = cfg.get(server, option)
    elif cfg.has_option("global", option):
        value = cfg.get("global", option)

    return value

def read_config(args):
    """ Read config file. """
    path = os.path.join(xdg_config_home, 'bmc', 'settings')
    if os.path.exists(path):
        cfg = configparser.ConfigParser()
        cfg.read(path)

        key = args.server
        if not key and cfg.has_option("global", "server"):
            key = cfg.get("global", "server")

        if not args.username:
            args.username = _get_cfg_value(cfg, key, "username")

        if not args.password:
            args.password = _get_cfg_value(cfg, key, "password")

        if cfg.has_option(key, "hostname"):
            args.server = cfg.get(key, "hostname")
        elif not args.server:
            args.server = key

        if cfg.has_option(key, "port"):
            args.server = "{0}:{1}".format(args.server, cfg.get(key, "port"))

    return args.server and args.username and args.password

def do_list(args):
    """ Send list request and show answer. """
    session = BMC(server=args.server, username=args.username, password=args.password)
    for i in session.list(args.path):
        print(i)

def do_enum(args):
    """ Send enumerate request and show answer. """
    session = BMC(server=args.server, username=args.username, password=args.password)
    print(json.dumps(session.enum(args.path), indent=4))

def do_get(args):
    """ Send get request for specified attribute. """
    session = BMC(server=args.server, username=args.username, password=args.password)
    print(json.dumps(session.get(args.path), indent=4))

def do_put(args):
    """ Send put request to change value of specified attribute. """
    session = BMC(server=args.server, username=args.username, password=args.password)
    if session.put("{0}/attr/{1}".format(args.path, args.attr), args.value):
        do_get(args)

if __name__ == '__main__':
    PARSER = argparse.ArgumentParser()
    PARSER.add_argument('-s', '--server', help='hostname or IP of BMC',
                        type=str)
    PARSER.add_argument('-u', '--username', help='username to log in on the BMC',
                        type=str)
    PARSER.add_argument('-p', '--password', help='password to log in on the BMC',
                        type=str)

    SUBPARSERS = PARSER.add_subparsers()

    LIST_ITEMS = SUBPARSERS.add_parser('list', help='List items on BMC')
    LIST_ITEMS.add_argument('path', help='Items path', type=str, nargs='?', default='/')
    LIST_ITEMS.set_defaults(func=do_list)

    ENUM_ITEMS = SUBPARSERS.add_parser('enum', help='Enumerate items on BMC')
    ENUM_ITEMS.add_argument('path', help='Items path', type=str, nargs='?', default='/')
    ENUM_ITEMS.set_defaults(func=do_enum)

    GET_ITEMS = SUBPARSERS.add_parser('get', help='Get specified item from BMC')
    GET_ITEMS.add_argument('path', help='Items path', type=str)
    GET_ITEMS.set_defaults(func=do_get)

    PUT_ITEMS = SUBPARSERS.add_parser('put', help='Put specified value into specified item on BMC')
    PUT_ITEMS.add_argument('path', help='Items path', type=str)
    PUT_ITEMS.add_argument('attr', help='Items attribute name', type=str)
    PUT_ITEMS.add_argument('value', help='Items attribute value', type=str)
    PUT_ITEMS.set_defaults(func=do_put)

    from urllib3 import disable_warnings, exceptions
    disable_warnings(exceptions.InsecureRequestWarning)

    ARGS = PARSER.parse_args()
    if read_config(ARGS) and 'func' in ARGS:
        ARGS.func(ARGS)
    else:
        PARSER.print_help()
