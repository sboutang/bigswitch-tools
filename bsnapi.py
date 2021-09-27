#!/usr/bin/env python3
import os
import re
import sys
import json
import requests
#from pygments import highlight
#from pygments.lexers import JsonLexer
#from pygments.formatters import TerminalFormatter
requests.packages.urllib3.disable_warnings()
username = os.getenv('BSNUSER')
password = os.getenv('BSNPASS')
p_name = os.path.basename(sys.argv[0])
method = 'get'
data = ''
## http logging
# import logging
# try:
#     import http.client as http_client
# except ImportError:
#     # Python 2
#     import httplib as http_client
# http_client.HTTPConnection.debuglevel = 1
# logging.basicConfig()
# logging.getLogger().setLevel(logging.DEBUG)
# requests_log = logging.getLogger("requests.packages.urllib3")
# requests_log.setLevel(logging.DEBUG)
# requests_log.propagate = True
## end http logging

def display_error(error_message):
    print(error_message)
    print("[OPTION] lab (API call on lab controller)")
    print("[OPTION] dc01 (API call on dc01 controller)")
    print("[OPTION] dc02 (API call on dc02 controller)")
    print("example: %s lab /api/v1/data/controller/core/version/appliance" % p_name)
    print("example: %s lab '/api/v1/data/controller/os/config/global/snmp/trap-host[server=\"10.1.1.1\"] {\"server\": \"10.1.1.1\"}' put" % p_name)
    sys.exit(1)

def controller_check():
    global base_url
    if sys.argv[1] == 'lab':
        base_url = "mn-pcclab-pnet-ctlr:8443"
    elif sys.argv[1] == 'dc01':
        base_url = "dc01-bcf-ctrl:8443"
    elif sys.argv[1] == 'dc02':
        base_url = "dc02-bcf-ctrl:8443"
    elif sys.argv[1] == 'bmf':
        base_url = "dc01-bmf-ctrl:8443"
    elif sys.argv[1] == 'bmfan':
        base_url = "dc01-bmf-an01:8443"
    else:
        error_message = "ERROR: incorrect controller"
        display_error(error_message)

def api_path_check():
    global api_check
    global path
    api_check = re.compile("^/api.*")
    api_check.match(sys.argv[2])
    if api_check.match(sys.argv[2]):
        path = sys.argv[2]
    else:
        error_message = "Check that your api call starts with /api"
        display_error(error_message)

def check_method():
    global method
    method_check = re.compile("get|patch|delete|put|post", re.IGNORECASE)
    if method_check.match(sys.argv[3]):
        method = str.lower(sys.argv[3])
    else:
        error_message = "ERROR: incorrect method must be one of: get, put, post"
        display_error(error_message)

def get_cookie():
    global cookie
    login_payload = '{"user":"%s", "password":"%s"}' % (username, password)
    login_headers = {'Content-Type': "application/json"}
    path = '/api/v1/auth/login'
    l = requests.post('https://' + base_url + path, headers=login_headers, data=login_payload, verify=False)
    if l.cookies:
        cookie = l.cookies['session_cookie']
    else:
        print("Couldn't get a session cookie, check username/password")
        sys.exit(1)

def kill_session():
    path = '/api/v1/data/controller/core/aaa/session[auth-token="%s"]' % cookie
    requests.delete('https://' + base_url + path, headers=headers, verify=False)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        error_message = "Usage: bsnapi [OPTION] [API Call]"
        display_error(error_message)

    if len(sys.argv) == 3:
        controller_check()
        api_path_check()

    elif len(sys.argv) == 4:
        controller_check()
        api_path_check()
        check_method()
        data = sys.argv[2]
        data_check = re.compile("(/api.+) ({.+})")
        if data_check.match(data):
            m = re.search(data_check, data)
            path_check = m.group(1)
            data = m.group(2)
            if api_check.match(path_check):
                path = path_check
        elif api_check.match(sys.argv[2]):
            path = sys.argv[2]
        elif method == get:
            path == sys.argv[2]
        else:
            error_message = "ERROR: api path and data incorrect"
            display_error(error_message)
    else:
        error_message = "invalid arguments"
        display_error(error_message)

    get_cookie()
    if cookie:
        session_cookie = 'session_cookie=%s' % cookie
        headers = {"content-type": "application/json", 'Cookie': session_cookie}
    else:
        print("I've just picked up a fault in the AE-35 unit.")
        sys.exit(1)
    if method:
        r = requests.request(method, 'https://' + base_url + path, headers=headers, data=data, verify=False)
    else:
        r = requests.get('https://' + base_url + path, headers=headers, verify=False)
    if r.content:
        parsed = json.loads(r.text)
        #print(highlight(r.text, JsonLexer(), TerminalFormatter()))
        print(json.dumps(parsed, indent=2, sort_keys=True))
    else:
        print(r.status_code)
        if r.status_code == 204:
            print("Success")
        r = requests.get('https://' + base_url + path, headers=headers, verify=False)
        parsed = json.loads(r.text)
        #print(highlight(r.text, JsonLexer(), TerminalFormatter()))
        print(json.dumps(parsed, indent=2, sort_keys=True))
    kill_session()
