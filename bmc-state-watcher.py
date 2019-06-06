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

import requests
import json
import os
import ssl
import websocket
import sys
import time
import argparse


from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

OPCODE_DATA = (websocket.ABNF.OPCODE_TEXT, websocket.ABNF.OPCODE_BINARY)

class App:
    def __init__(self, host, username, password):
        print("--- initialize ---")
        self.start_time = time.time()
        self.url = "https://{0}".format(host)
        self.session = requests.Session()
        self.login(username, password)
        self.subscribe(host)

    def get(self, path, attr=None):
        url = self.url + path
        if attr:
            url = url + '/attr/' + attr
        r = self.session.get(url, verify=False)

        j = r.json()
        if j['status'] != 'ok':
            raise Exception("Failed to query get: \n" + r.text)

        return j['data']

    def trace_message(self, msg):
        sys.stdout.write("%12.03f: %s\n" % ((time.time() - self.start_time), msg))
        sys.stdout.flush()

    def strip_value(self, value):
        s = str(value)
        n = s.rfind('.') + 1
        return s[n:]

    def show_attr(self, path, attr):
        try:
            self.trace_message('%s: %s' % (attr, self.strip_value(self.get(path, attr))))
        except (Exception):
            # Skip attr if it is not available yet.
            pass

    def login(self, username, password):
        r = self.session.post(self.url + '/login',
                json={'data': [username, password], 'force': True},
                verify=False)
        j = r.json()
        if j['status'] != 'ok':
            raise Exception('Failed to login: %r\n' % r.text)

        if 'SESSION' in self.session.cookies.keys():
            self.session.headers.update({
                'X-Auth-Token': self.session.cookies['SESSION']
                })

        self.trace_message('Login succeeded!')

        self.show_attr('/xyz/openbmc_project/state/bmc0', 'CurrentBMCState')
        self.show_attr('/xyz/openbmc_project/state/chassis0', 'CurrentPowerState')
        self.show_attr('/xyz/openbmc_project/state/host0', 'CurrentHostState')
        self.show_attr('/xyz/openbmc_project/state/host0', 'OperatingSystemState')
        self.show_attr('/xyz/openbmc_project/state/host0', 'BootProgress')

    def subscribe(self, host):
        self.ws = websocket.create_connection(
                                "wss://{0}/subscribe".format(host),
                                sslopt={
                                    "cert_reqs": ssl.CERT_NONE, 
                                    "check_hostname": False},
                                cookie = "; ".join([
                                    ("%s=%s" % (k,v)) 
                                    for k,v in self.session.cookies.items()]))
    def _recv(self):
        try:
            frame = self.ws.recv_frame()
        except websocket.WebSocketException as e:
            self.trace_message("websocket.WebSocketException: %r" % e)
            return websocket.ABNF.OPCODE_CLOSE, None

        if not frame:
            raise websocket.WebSocketException("Not a valid frame %s" % frame)
        elif frame.opcode in OPCODE_DATA:
            return frame.opcode, frame.data
        elif frame.opcode == websocket.ABNF.OPCODE_CLOSE:
            self.ws.send_close()
            return frame.opcode, None
        elif frame.opcode == websocket.ABNF.OPCODE_PING:
            self.ws.pong(frame.data)
            return frame.opcode, frame.data

        return frame.opcode, frame.data

    def run_forever(self):
        print("--- start watching ---")

        if self.ws:
            self.ws.send(json.dumps({
                    'paths': [
                        '/xyz/openbmc_project/state/bmc0',
                        '/xyz/openbmc_project/state/chassis0',
                        '/xyz/openbmc_project/state/host0' ],
                    'interfaces': [
                        'xyz.openbmc_project.State.BMC',
                        'xyz.openbmc_project.State.Chassis',
                        'xyz.openbmc_project.State.Host',
                        'xyz.openbmc_project.State.OperatingSystem.Status',
                        'xyz.openbmc_project.State.Boot.Progress' ]}))

        while self.ws:
            opcode, data = self._recv()

            try:
                j = json.loads(data)
                if 'properties' in j:
                    for p in j['properties']:
                        self.trace_message("%s: %s" % (p, self.strip_value(j['properties'][p])))

            except (ValueError, TypeError):
                pass

            if opcode == websocket.ABNF.OPCODE_CLOSE:
                self.trace_message("Websocket closed!")
                break


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--username', 
                        help='Username to log in  on the BMC', 
                        type=str, nargs='?', default='admin')
    parser.add_argument('-p', '--password', 
                        help='Password to log in on the BMC',
                        type=str, nargs='?', default='admin')
    parser.add_argument('host', 
                        help='Hostname or IP address of the BMC',
                        type=str)

    args = parser.parse_args()

    app = App(args.host, args.username, args.password)
    try:
        app.run_forever()
    except (KeyboardInterrupt):
        pass
