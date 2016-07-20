#!/usr/bin/env python
# -*- coding=utf-8 -*-
from __future__ import print_function

import argparse
import base64
import cPickle
import os
import socket
import sys
import time
import urlparse
import logging
from ConfigParser import SafeConfigParser

import requests
from transitions import Machine, State


logger = logging.getLogger(__file__)

class IOState(State):
    def __init__(self, name, on_enter=None, on_exit=None,
                 ignore_invalid_triggers=False, multiline=False, handler=None):
        State.__init__(self, name, on_enter, on_exit, ignore_invalid_triggers)
        self.multiline = multiline
        self.handler = handler


def read_config():
    hd = os.path.expanduser('~')
    config_path = os.path.join(hd, '.rsc')
    config = SafeConfigParser()
    config.read(os.path.join(config_path, 'config.ini'))
    return config


def save_config(config):
    hd = os.path.expanduser('~')
    config_path = os.path.join(hd, '.rsc')
    if not os.path.isdir(config_path):
        os.mkdir(config_path)
    with open(os.path.join(config_path, 'config.ini'), 'wb') as configfile:
        config.write(configfile)


def read_uri(config):
    return config.get("main","uri")

class Cli(object):
    def explain_url(self):
        print("What is the URL? (<scheme>://<netloc>/<path>;<params>?<query>#<fragment> format please):")
        print("[{}]: ".format(self.url if self.url is not None else " "), end="")

    def validate_url(self, line):
        if len(line) == 0 and not self.url:
            self.explain_url()
            return
        elif len(line) > 0:
            result = urlparse.urlparse(line)
            self.url = line
            self.config.set("history", "url", line)

        self.ask_for_method()

    methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]

    def explain_method(self):
        print("Choose method:")
        for i, method in enumerate(Cli.methods):
            print("[{0}] {1}".format(i + 1, method))
        print("[{}]: ".format(self.method if self.method is not None else " "), end="")

    def validate_method(self, line):
        try:
            if len(line) > 0:
                method_i = int(line)
                method = Cli.methods[method_i - 1]
                self.method = method
                self.config.set("history", "method", method)
            else:
                if not self.method:
                    self.explain_method()
                    return
        except Exception:
            self.explain_method()
            return

        if self.method == "GET" or self.method == "DELETE":
            self.ask_for_special_headers()
        else:
            self.ask_for_payload()

    def explain_payload(self):
        print("Method chosen suggests you have example payload. Press Ctrl-D when finished:")



    def validate_payload(self, content):

        if len(content.strip())==0:
            #self.ask_for_special_headers()
            self.payload = None
        else:
            self.payload = content
            #self.ask_mime()
        self.ask_for_special_headers()

    mimes = ["application/x-www-form-urlencoded", "application/json", "application/xml"]

    def explain_mime(self):
        pass

    def validate_mime(self, line):
        pass

    def explain_mime(self):
        print("Choose MIME:")
        for i, m in enumerate(Cli.mimes):
            print("[{0}] {1}".format(i + 1, m))
        print("[{}]: ".format(self.mime if self.mime is not None else " "), end="")


    def validate_mime(self, line):
        try:
            if len(line) > 0:
                m_i = int(line)
                mime = Cli.mimes[m_i - 1]
                self.mime = mime
                self.config.set("history", "mime", mime)
            else:
                if not self.method:
                    self.explain_method()
                    return
        except Exception:
            self.explain_method()
            return

        self.ask_for_special_headers()


    def explain_authheaders(self):

        print(
            "Do you have some special required http headers? Paste them in format header_name=header_value. Leave empty if you finished or want to skip.")
        print("[ ]: ", end="")

    def validate_authheaders(self, line):

        if len(line) == 0:
            self.ask_for_next()
        else:
            # add to list
            self.headers.append(line.strip())
            print("[ ]: ", end="")
            pass

    def explain_other(self):
        print("Do you have another example? Y/N")
        print('[N]: ', end='')

    def validate_other(self, line):
        if 'N' == line.upper() or len(line) == 0:
            self.do_scan()
        elif 'Y' == line.upper():
            self.ask_for_url()
        else:
            self.explain_other()

    def run_scan(self):

        payload = {
            "url": self.url,
            "method": self.method,
            "content": self.payload,
            "headers": self.headers
        }
        r = requests.post(read_uri(self.config) + '/api/snippet/download',headers = {"Authorization":"Bearer " + self.config.get("main","token")},  json=payload)
        size = int(r.headers['Content-Length'].strip())
        bytes = 0
        for buf in r.iter_content(1024):
            if buf:
                progress(bytes, size, "downloading attacks")
                bytes += len(buf)
        progress(1, 1, "downloaded attacks")
        print("\nattacks downloaded")
        if r.status_code == 200:
            resp = r.json()
            attacks = cPickle.loads(resp['payloads'].encode("utf-8"))
            attacks_with_responses = {}
            for k, v in attacks.iteritems():
                responses = do_attack(k, v)
                attacks_with_responses[k] = responses

            payload['payloads'] = cPickle.dumps(attacks_with_responses)
            r = requests.post(read_uri(self.config) + '/api/snippet/upload',headers = {"Authorization":"Bearer " + self.config.get("main","token")}, json=payload)
            print("Report:")
            self.endpoints_with_methods = r.json()['report']
            self.report_url = r.json()['view']
            self.show_result()

    def present_report(self):
        issues = set()
        for endpoint in self.endpoints_with_methods:
            for v in endpoint.get('vulnerabilities'):
                issues.add(v.get('name'))

        for i in issues:
            print("{}, level high".format(i))

        print("For full report head to: {}{}".format(read_uri(self.config), self.report_url))

    #              -----------------------------------\
    #             V                                   |
    #  > helo > url > method  >  authheaders? >   other call?  > scan > result
    #                    v         /\
    #                  payload >  mime?
    states = [
        "start",
        "hello",
        IOState(name='url', on_enter='explain_url', handler=validate_url, multiline=False),
        IOState(name="method", on_enter='explain_method', handler=validate_method, multiline=False),
        IOState(name="payload", on_enter='explain_payload', handler=validate_payload, multiline=True),
        IOState(name="mime", on_enter='explain_mime', handler=validate_mime, multiline=False),
        IOState(name="authheaders", on_enter='explain_authheaders', handler=validate_authheaders, multiline=False),
        IOState(name="other", on_enter='explain_other', handler=validate_other, multiline=False),
        State(name="scan", on_enter="run_scan"),
        State(name="result", on_enter="present_report")
    ]

    transitions = [
        {'trigger': 'say_hello', 'source': 'start', 'dest': 'hello'},
        {'trigger': 'ask_for_url', 'source': ['hello', 'other'], 'dest': 'url'},
        {'trigger': 'ask_for_method', 'source': 'url', 'dest': 'method'},
        {'trigger': 'ask_for_payload', 'source': 'method', 'dest': 'payload'},
        {'trigger': 'ask_mime', 'source': 'payload', 'dest': 'mime'},
        {'trigger': 'ask_for_special_headers', 'source': ['payload','mime', 'method'], 'dest': 'authheaders'},
        {'trigger': 'ask_for_next', 'source': 'authheaders', 'dest': 'scan'},
        {'trigger': 'do_scan', 'source': 'other', 'dest': 'scan'},
        {'trigger': 'show_result', 'source': 'scan', 'dest': 'result'},

    ]

    def welcome_message(self):
        print("This is Rest Secured CLI scanner. We will ask few questions")

    def __init__(self, config):
        # Initialize the state machine
        self.machine = Machine(model=self, states=Cli.states, initial='start', transitions=Cli.transitions)
        self.machine.on_enter_hello("welcome_message")
        if config.has_section("history"):
            if config.has_option("history", "url"):
                self.url = config.get("history", "url")
            else:
                self.url = None
            if config.has_option("history", "mime"):
                self.mime = config.get("history", "mime")
            else:
                self.mime = None
            if config.has_option("history", "method"):
                self.method = config.get("history", "method")
            else:
                self.method = None
            if config.has_option("history", "payload"):
                self.payload = base64.b64decode(config.get("history", "payload"))
            else:
                self.payload = None
        else:
            config.add_section("history")
            self.url = None
            self.method = None
            self.payload = None
        self.headers = []
        self.config = config

    def start(self):
        self.say_hello()
        self.ask_for_url()

    def is_finished(self):
        return self.state == "result"

    def input(self):
        s = self.machine.get_state(self.state)
        logger.debug("Reading input while in state - {}".format(s.name))
        if isinstance(s, IOState):
            logger.debug("Reading input while in state - {}, multi - {}".format(s.name, s.multiline))
            if s.multiline:
                content = ""
                for line in sys.stdin:
                    content += line
                sys.stdin.readline()
            else:
                line = sys.stdin.readline()
                content = line.strip()

            s.handler(self, content)
        pass


def authorize_cli(args):
    c = read_config()

    # test call
    r = requests.get(args.uri + '/api/ping', headers = {"Authorization":"Bearer " + args.token})

    if r.status_code == 200:
        # if succeeds, save
        if not c.has_section("main"):
            c.add_section('main')
        c.set("main", "token", args.token)
        c.set("main","uri",args.uri)
        save_config(c)
        print (u" ✓ Cli is authorized to run scans.")
    else:
        print (u" ✕ Something went wrong, check token.")


def progress(count, total, suffix=''):
    bar_len = 60
    filled_len = int(round(bar_len * count / float(total)))

    percents = round(100.0 * count / float(total), 1)
    bar = '=' * filled_len + '-' * (bar_len - filled_len)

    sys.stdout.write('\r[%s] %s%s ...%s' % (bar, percents, '%', suffix))
    sys.stdout.flush()


def setup_socket(host, port, ssl):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    sock.connect((host, port))
    if ssl:
        import ssl
        sock = ssl.wrap_socket(sock)
    return sock


def do_attack(url, attacks):
    parsed = urlparse.urlparse(url)
    netloc = parsed.netloc
    ssl = False
    if parsed.scheme == "https":
        port = 443
        ssl = True
    else:
        port = 80
    if ":" in netloc:
        netloc, port = netloc.split(":", 1)

    for i, attack in enumerate(attacks):
        progress(i, len(attacks), attack['injection'].get('attack'))
        sock = setup_socket(netloc, int(port), ssl)
        start = time.time()
        request = attack['request']
        sock.send(request)
        if ssl:
            received = sock.recv(10000000)
        else:
            received = sock.recv(10000000, socket.MSG_WAITALL)
        end = time.time()
        elapsed = end - start
        method = request[:request.find(' ')].upper()
        attack['method'] = method
        attack['url'] = url
        attack['response'] = received
        attack['elapsed'] = elapsed
        # {"data": data, "injection": inj, "node":is_final_node}
    return attacks


def scan_cli(args):
    try:
        config = read_config()
        c = Cli(config)
        c.start()
        while not c.is_finished():
            c.input()
    finally:
        save_config(config)


parser = argparse.ArgumentParser(description='Rest Secured co-pilot', prog="rsc")
parser.add_argument("-v", type=bool, dest='verbose', required=False,
                           help="set verbose logging")
subparsers = parser.add_subparsers()
parser_foo = subparsers.add_parser('authorize')
parser_foo.add_argument('token', type=str, help="Authorization token from Rest Secured")
parser_foo.add_argument('uri', type=str, default='https://www.restsecured.xyz', help="Override Rest Secured URI")
parser_foo.set_defaults(func=authorize_cli)

parser_bar = subparsers.add_parser('scan')
parser_bar.set_defaults(func=scan_cli)

if __name__ == '__main__':
    args = parser.parse_args(sys.argv[1:])
    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        ch.setLevel(logging.DEBUG)
    args.func(args)
