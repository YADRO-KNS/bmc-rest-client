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
""" Example of using websocket to subscribe on BMC events. """

import argparse
import json
import ssl
import sys
import time
import requests
import websocket

from urllib3 import disable_warnings, exceptions
disable_warnings(exceptions.InsecureRequestWarning)

OPCODE_DATA = (websocket.ABNF.OPCODE_TEXT, websocket.ABNF.OPCODE_BINARY)

def strip_value(value):
    """ Remove interface name from DBus enum values """
    strval = str(value)
    idx = strval.rfind('.') + 1
    return strval[idx:]

class App:
    """ Main application class """
    def __init__(self, host, username, password):
        print("--- initialize ---")
        self.start_time = time.time()
        self.url = "https://{0}".format(host)
        self.session = requests.Session()
        self.login(username, password)
        self.subscribe(host)

    def get(self, path, attr=None):
        """ Get specified attribute from REST. """
        url = self.url + path
        if attr:
            url = url + '/attr/' + attr
        req = self.session.get(url, verify=False)

        j = req.json()
        if j['status'] != 'ok':
            raise Exception("Failed to query get: \n" + req.text)

        return j['data']

    def trace_message(self, msg):
        """ Display tracing message """
        sys.stdout.write("%12.03f: %s\n" % ((time.time() - self.start_time), msg))
        sys.stdout.flush()

    def show_attr(self, path, attr):
        """ Display attribute and its value """
        try:
            self.trace_message('%s: %s' % (attr, strip_value(self.get(path, attr))))
        except (Exception):
            # Skip attr if it is not available yet.
            pass

    def login(self, username, password):
        """ Send login request """
        req = self.session.post(self.url + '/login',
                                json={'data': [username, password],
                                      'force': True},
                                verify=False)
        j = req.json()
        if j['status'] != 'ok':
            raise Exception('Failed to login: %r\n' % req.text)

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
        """ Create websocket session and subscribe to requred events. """
        self.sock = websocket.create_connection(
            "wss://{0}/subscribe".format(host),
            sslopt={"cert_reqs": ssl.CERT_NONE,
                    "check_hostname": False},
            cookie="; ".join([
                ("%s=%s" % (k, v))
                for k, v in self.session.cookies.items()]))

    def _recv(self):
        try:
            frame = self.sock.recv_frame()
        except websocket.WebSocketException as err:
            self.trace_message("websocket.WebSocketException: %r" % err)
            return websocket.ABNF.OPCODE_CLOSE, None

        if not frame:
            raise websocket.WebSocketException("Not a valid frame %s" % frame)

        if frame.opcode == websocket.ABNF.OPCODE_CLOSE:
            self.sock.send_close()
        elif frame.opcode == websocket.ABNF.OPCODE_PING:
            self.sock.pong(frame.data)

        return frame.opcode, frame.data

    def run_forever(self):
        """ Main loop """
        print("--- start watching ---")

        if self.sock:
            self.sock.send(json.dumps({
                'paths': [
                    '/xyz/openbmc_project/state/bmc0',
                    '/xyz/openbmc_project/state/chassis0',
                    '/xyz/openbmc_project/state/host0'],
                'interfaces': [
                    'xyz.openbmc_project.State.BMC',
                    'xyz.openbmc_project.State.Chassis',
                    'xyz.openbmc_project.State.Host',
                    'xyz.openbmc_project.State.OperatingSystem.Status',
                    'xyz.openbmc_project.State.Boot.Progress']}))

        while self.sock:
            opcode, data = self._recv()

            try:
                j = json.loads(data)
                if 'properties' in j:
                    for name, val in j['properties'].items():
                        self.trace_message("%s: %s" % (name, strip_value(val)))
            except (ValueError, TypeError):
                pass

            if opcode == websocket.ABNF.OPCODE_CLOSE:
                self.trace_message("Websocket closed!")
                break


if __name__ == '__main__':
    PARSER = argparse.ArgumentParser()
    PARSER.add_argument('-u', '--username',
                        help='Username to log in  on the BMC',
                        type=str, nargs='?', default='admin')
    PARSER.add_argument('-p', '--password',
                        help='Password to log in on the BMC',
                        type=str, nargs='?', default='admin')
    PARSER.add_argument('host',
                        help='Hostname or IP address of the BMC',
                        type=str)

    ARGS = PARSER.parse_args()

    APP = App(ARGS.host, ARGS.username, ARGS.password)
    try:
        APP.run_forever()
    except KeyboardInterrupt:
        pass
