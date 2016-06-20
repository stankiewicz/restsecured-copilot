#!/usr/bin/env python

import argparse
import os
import sys

import cPickle
import urlparse
import socket
from time import sleep
import time
import requests


def authorize_cli(args):
    print args.token


methods = ["GET","POST","PUT","DELETE","PATCH"]

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
        netloc, port = netloc.split(":",1)
    for i, attack in enumerate(attacks):
        progress(i,len(attacks), attack['injection'].get('attack'))
        sock = setup_socket(netloc,int(port),ssl)
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
        #{"data": data, "injection": inj, "node":is_final_node}
    return attacks

def scan_cli(args):
    print "What is the URL?"
    url = sys.stdin.readline().strip()
    print "Choose method:"
    for i, method in enumerate(methods):
        print "[{0}] {1}".format(i+1,method)

    userinput = sys.stdin.readline()
    method_i = int(userinput)
    method = methods[method_i-1]
    payload = {
        "url": url,
        "method": method,
        "content": None
    }
    r = requests.post(os.environ.get('RSC_URI')+'/api/snippet/download', json=payload)
    size = int(r.headers['Content-Length'].strip())
    bytes = 0
    for buf in r.iter_content(1024):
        if buf:
            progress(bytes, size, "downloading attacks")
            bytes += len(buf)
    progress(1, 1, "downloaded attacks")
    print "\nattacks downloaded"
    if r.status_code == 200:
        resp = r.json()
        attacks = cPickle.loads(resp['payloads'].encode("utf-8"))
        attacks_with_responses = {}
        for k,v in attacks.iteritems():
            responses = do_attack(k, v)
            attacks_with_responses[k] = responses

        payload['payloads'] = cPickle.dumps(attacks_with_responses)
        r = requests.post(os.environ.get('RSC_URI')+'/api/snippet/upload', json=payload)
        print "Report:"
        endpoints_with_methods = r.json()['report']
        issues = set()
        for endpoint in endpoints_with_methods:
            for v in endpoint.get('vulnerabilities'):
                issues.add(v.get('name'))

        for i in issues:
            print "{}, level high".format(i)

        print "For full report head to: https://www.restsecured.xyz/blablabla1234"

parser = argparse.ArgumentParser(description='Rest Secured co-pilot',prog="rsc")
subparsers = parser.add_subparsers()
parser_foo = subparsers.add_parser('authorize')
parser_foo.add_argument('token', type=str)
parser_foo.set_defaults(func=authorize_cli)

parser_bar = subparsers.add_parser('scan')
parser_bar.set_defaults(func=scan_cli)

if __name__ == '__main__':
    os.environ['RSC_URI']= 'http://127.0.0.1:5000'
    args = parser.parse_args(sys.argv[1:])
    args.func(args)
