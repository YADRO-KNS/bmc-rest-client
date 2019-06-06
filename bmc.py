#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import requests
import json

try:
    import configparser
except ImportError:
    import ConfigParser as configparser

from xdg.BaseDirectory import xdg_config_home
import os


class BMC:
    def __init__(self, server, username, password):
        self.url = "https://{0}".format(server)
        self.session = requests.Session()
        self.login(username, password)

    def login(self, username, password):
        r = self.session.post(self.url + '/login',
                              json={'data': [username, password]},
                              verify=False)
        j = r.json()
        if j['status'] != 'ok':
            raise Exception("Failed to login: \n" + r.text)

        if 'SESSION' in self.session.cookies:
            self.session.headers.update({
                'X-Auth-Token': self.session.cookies['SESSION']
                })

    def list(self, path):
        r = self.session.get(self.url + path + '/list',
                             verify=False)
        j = r.json()
        if j['status'] != 'ok':
            raise Exception("Failed to query list: \n" + r.text)

        l = j['data']
        return l

    def enum(self, path):
        r = self.session.get(self.url + path + '/enumerate',
                             verify=False)
        j = r.json()
        if j['status'] != 'ok':
            raise Exception("Failed to query enumerate: \n" + r.text)

        return j['data']

    def get(self, path):
        r = self.session.get(self.url + path, verify=False)

        j = r.json()
        if j['status'] != 'ok':
            raise Exception("Failed to query get: \n" + r.text)

        return j['data']

    def put(self, path, value):
        r = self.session.put(self.url + path,
                             json={'data': value},
                             verify=False)
        j = r.json()
        if j['status'] != 'ok':
            raise Exception("Failed to qeury put: \n" + r.text)

        return True

def _get_cfg_value(cfg, server, option):
    if cfg.has_option(server, option):
        return cfg.get(server, option)
    elif cfg.has_option("global", option):
        return cfg.get("global", option)

    return None

def read_config(args):
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
    s = BMC(server=args.server, username=args.username, password=args.password)
    for i in s.list(args.path):
        print (i)

def do_enum(args):
    s = BMC(server=args.server, username=args.username, password=args.password)
    print (json.dumps(s.enum(args.path), indent=4))

def do_get(args):
    s = BMC(server=args.server, username=args.username, password=args.password)
    print (json.dumps(s.get(args.path), indent=4))

def do_put(args):
    s = BMC(server=args.server, username=args.username, password=args.password)
    if s.put("{0}/attr/{1}".format(args.path, args.attr), args.value):
        do_get(args)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--server', help='hostname or IP of BMC',
                        type=str)
    parser.add_argument('-u', '--username', help='username to log in on the BMC',
                        type=str)
    parser.add_argument('-p', '--password', help='password to log in on the BMC',
                        type=str)

    subparsers = parser.add_subparsers()

    list_items = subparsers.add_parser('list', help='List items on BMC')
    list_items.add_argument('path', help='Items path', type=str, nargs='?', default='/')
    list_items.set_defaults(func=do_list)

    enum_items = subparsers.add_parser('enum', help='Enumerate items on BMC')
    enum_items.add_argument('path', help='Items path', type=str, nargs='?', default='/')
    enum_items.set_defaults(func=do_enum)

    get_items = subparsers.add_parser('get', help='Get specified item from BMC')
    get_items.add_argument('path', help='Items path', type=str)
    get_items.set_defaults(func=do_get)

    put_items = subparsers.add_parser('put', help='Put specified value into specified item on BMC')
    put_items.add_argument('path', help='Items path', type=str)
    put_items.add_argument('attr', help='Items attribute name', type=str)
    put_items.add_argument('value', help='Items attribute value', type=str)
    put_items.set_defaults(func=do_put)

    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    args = parser.parse_args()
    if read_config(args) and 'func' in args:
        args.func(args)
    else:
        parser.print_help()

