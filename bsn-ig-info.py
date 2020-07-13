#!/usr/bin/env python3
import argparse
import os
import sys
import requests

requests.packages.urllib3.disable_warnings()
username = os.getenv('BSNUSER')
password = os.environ.get('BSNPASS')
p_name = os.path.basename(sys.argv[0])
parser = argparse.ArgumentParser(description='BCF interface group information')
parser.add_argument('controller', type=str, help='lab, dc01, dc02')
parser.add_argument(
    'interface_group_name', type=str, help='interface group example: mn-pcclab-core-rt01')
args = parser.parse_args()
base_url = ''
cookie = ''
## http logging
#import logging
#try:
#    import http.client as http_client
#except ImportError:
#    # Python 2
#    import httplib as http_client
#http_client.HTTPConnection.debuglevel = 1
#logging.basicConfig()
#logging.getLogger().setLevel(logging.DEBUG)
#requests_log = logging.getLogger("requests.packages.urllib3")
#requests_log.setLevel(logging.DEBUG)
#requests_log.propagate = True
## end http logging

def display_error(error_message):
    print(error_message)
    print("[OPTION] lab interface_group_name")
    print("[OPTION] dc01 interface_group_name")
    print("[OPTION] dc02 interface_group_name")
    print("example: %s lab mn-pcclab-core-rt01" % p_name)
    sys.exit(1)

def controller_check(controller):
    global base_url
    if controller == 'lab':
        base_url = "mn-pcclab-pnet-ctlr:8443"
    elif controller == 'dc01':
        base_url = "dc01-bcf-ctrl:8443"
    elif controller == 'dc02':
        base_url = "dc02-bcf-ctrl:8443"
    else:
        error_message = "ERROR: incorrect controller"
        display_error(error_message)
    return base_url

def list_all_ig():
    if cookie:
        session_cookie = 'session_cookie=%s' % cookie
        headers = {"content-type": "application/json", 'Cookie': session_cookie}
        ig_list = []
        path = '/api/v1/data/controller/applications/bcf/info/fabric/interface-group/summary'
        groups = requests.get('https://' + base_url + path, headers=headers, verify=False).json()
        print("Use one of these interface groups:")
        for ig in groups:
            if ig['mode'] == 'static-auto-controller-inband':
                ig.pop("name", None)
            else:
                ig_list.append(ig['name'])
        sorted_ig = sorted(set(ig_list))
        for i in sorted_ig:
            print(i)
        kill_session()
        sys.exit(1)
    else:
        print("I've just picked up a fault in the AE-35 unit.")
        sys.exit(1)

def ig_state(ig_name):
    if cookie:
        session_cookie = 'session_cookie=%s' % cookie
        headers = {"content-type": "application/json", 'Cookie': session_cookie}
        path = '/api/v1/data/controller/applications/bcf/info/fabric/interface-group/detail[name="%s"]' % ig_name
        data = requests.get('https://' + base_url + path, headers=headers, verify=False).json()
        if 'interface' not in data[0]:
            print("%s has no members assigned" % ig_name)
        else:
            for x in data:
                print(x['name'])
            for y in x['interface']:
                if y['interface-down-reason'] != "None":
                    print("    mode: %s leaf-group: %s switch: %s interface: %s phy-state: %s op-state: %s reason: %s" % (y['mode'], y['leaf-group'], y['member-info']['switch-name'], y['member-info']['interface-name'], y['phy-state'], y['op-state'], y['interface-down-reason']))
                else:
                    print("    mode: %s leaf-group: %s switch: %s interface: %s phy-state: %s op-state: %s" % (y['mode'], y['leaf-group'], y['member-info']['switch-name'], y['member-info']['interface-name'], y['phy-state'], y['op-state']))

def ig_lookup(ig_name):
    if cookie:
        session_cookie = 'session_cookie=%s' % cookie
        headers = {"content-type": "application/json", 'Cookie': session_cookie}
    else:
        print("I've just picked up a fault in the AE-35 unit.")
        sys.exit(1)
    if ig_name == '?':
        list_all_ig()
    else:
        l = []
        path = '/api/v1/data/controller/applications/bcf/info/endpoint-manager/member-rule'
        members = requests.get('https://' + base_url + path, headers=headers, verify=False).json()
        path = '/api/v1/data/controller/applications/bcf/info/fabric/interface-group/summary'
        summary = requests.get('https://' + base_url + path, headers=headers, verify=False).json()
        sum_name = []
        for z in summary:
            sum_name.append(z['name'])
        for x in members:
            if 'interface-group' in x.keys():
                if x['vlan'] is -1:
                    x['vlan'] = "untagged"
                if x['interface-group'] == ig_name:
                    l.append("interface_group: %s tenant: %s segment: %s vlan_id: %s" %
                             (x['interface-group'], x['tenant'], x['segment'], x['vlan']))
    sorted_list = sorted(set(l))
    if ig_name not in sum_name and len(sorted_list) == 0:
        print("interface_group: %s does not exist on this fabric" % ig_name)
        list_all_ig()
    elif ig_name in sum_name and len(sorted_list) == 0:
        ig_state(ig_name)
        print("interface_group: %s has no configured membership rules" % ig_name)
    else:
        ig_state(ig_name)
        print()
        for i in sorted_list:
            print(i)

def get_cookie(base_url):
    global cookie
    login_payload = '{"user":"%s", "password":"%s"}' % (username, password)
    login_headers = {'Content-Type': "application/json"}
    path = '/api/v1/auth/login'
    l = requests.post(
        'https://' + base_url + path, headers=login_headers, data=login_payload, verify=False)
    if l.cookies:
        cookie = l.cookies['session_cookie']
    else:
        print("Couldn't get a session cookie, check username/password")
        sys.exit(1)
    return cookie

def kill_session():
    session_cookie = 'session_cookie=%s' % cookie
    headers = {"content-type": "application/json", 'Cookie': session_cookie}
    path = '/api/v1/data/controller/core/aaa/session[auth-token="%s"]' % cookie
    requests.delete('https://' + base_url + path, headers=headers, verify=False)

if __name__ == '__main__':
    get_cookie(controller_check(args.controller))
    ig_lookup(args.interface_group_name)
    kill_session()
