#!/usr/bin/env python3
import re
import argparse
import os
import sys
import requests

requests.packages.urllib3.disable_warnings()
username = os.getenv('BSNUSER')
password = os.environ.get('BSNPASS')
p_name = os.path.basename(sys.argv[0])
parser = argparse.ArgumentParser(description='BCF segment information')
parser.add_argument('controller', type=str, help='lab, dc01, dc02')
parser.add_argument('vlan', type=str, help='vlan number example: 123')
args = parser.parse_args()

def display_error(error_message):
    print(error_message)
    print("[OPTION] lab (API call on lab controller)")
    print("[OPTION] dc01 (API call on dc01 controller)")
    print("[OPTION] dc02 (API call on dc02 controller)")
    print("example: %s lab 123" % p_name)
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

def vlan_check(vlan):
    vlan_digit_check = re.compile("^\d+$")
    if vlan_digit_check.match(vlan):
        segment = "vlan" + vlan
    else:
        segment = vlan
    return segment

def segment_lookup(segment):
    if cookie:
        session_cookie = 'session_cookie=%s' % cookie
        headers = {"content-type": "application/json", 'Cookie': session_cookie}
    else:
        print("I've just picked up a fault in the AE-35 unit.")
        sys.exit(1)
    if segment == '?':
        segment_list = []
        path = '/api/v1/data/controller/applications/bcf/info/endpoint-manager/segment'
        s = requests.get('https://' + base_url + path, headers=headers, verify=False).json()
        print("Use one of these VLAN segments:")
        for i in s:
            segment_list.append(i['name'])
        sorted_segments = sorted(set(segment_list))
        for i in sorted_segments:
            print(i)
        kill_session()
        sys.exit(1)
    else:
        path = '/api/v1/data/controller/applications/bcf/info/endpoint-manager/segment[name="%s"]' % segment
        t = requests.get('https://' + base_url + path, headers=headers, verify=False).json()

    if len(t) == 0:
        print("segment: %s does not exist in any tenant on this fabric" % segment)
    else:
        tenant = t[0]['tenant']
        path = '/api/v1/data/controller/applications/bcf/tenant[name="%s"][segment/name="%s"]?select=segment[name="%s"]'\
            % (tenant, segment, segment)
        r = requests.get('https://' + base_url + path, headers=headers, verify=False).json()
        print("tenant: %s" % tenant)
        print("  segment: %s" % segment)
        check = r[0]['segment'][0].keys()
        if 'interface-group-membership-rule' not in check:
            print("no configured interface groups")
        else:
            for interface_group in r[0]['segment'][0]['interface-group-membership-rule']:
                if interface_group['vlan'] is -1:
                    interface_group['vlan'] = "untagged"
                print("  interface_group: %s vlan: %s" % (interface_group['interface-group'], interface_group['vlan']))

def get_cookie(base_url):
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
    return cookie

def kill_session():
    session_cookie = 'session_cookie=%s' % cookie
    headers = {"content-type": "application/json", 'Cookie': session_cookie}
    path = '/api/v1/data/controller/core/aaa/session[auth-token="%s"]' % cookie
    requests.delete('https://' + base_url + path, headers=headers, verify=False)

if __name__ == '__main__':
    get_cookie(controller_check(args.controller))
    segment_lookup(vlan_check(args.vlan))
    kill_session()
