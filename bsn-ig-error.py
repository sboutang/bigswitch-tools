#!/usr/bin/env python3
import argparse
import os
import json
import sys
import requests
from tabulate import tabulate

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
        for ig in groups:
            if ig['mode'] == 'static-auto-controller-inband':
                ig.pop("name", None)
            else:
                ig_list.append(ig['name'])
        sorted_ig = sorted(set(ig_list))
        return sorted_ig
    else:
        print("I've just picked up a fault in the AE-35 unit.")
        sys.exit(1)

def get_stats(switch_members, ig_name):
    session_cookie = 'session_cookie=%s' % cookie
    headers = {"content-type": "application/json", 'Cookie': session_cookie}
    path = '/api/v1/data/controller/applications/bcf/info/statistic/interface-counter[interface/name="%s"]\
        [switch-dpid="%s"]?select=interface[name="%s"]'\
        % (switch_members['interface-name'], switch_members['dpid'], switch_members['interface-name'])
    r_stats = requests.get('https://' + base_url + path, headers=headers, verify=False).json()
    if r_stats:
        stats = r_stats[0]['interface'][0]['counter']
        switch_name = switch_members['switch-name']
        int_name = switch_members['interface-name']
        rx_bad_vlan_pkt = stats['rx-bad-vlan-packet']
        rx_crc_error = stats['rx-crc-error']
        rx_error = stats['rx-error']
        tx_error = stats['tx-error']
        rx_drop = stats['rx-drop']
        tx_drop = stats['tx-drop']
        print("%s:" % ig_name)
        output = [{"switch_name": switch_name, "interface_name": int_name, "rx_bad_vlan_pkt": rx_bad_vlan_pkt, "rx_crc_error":\
                   rx_crc_error, "rx_error": rx_error, "tx_error": tx_error, "rx_drop": rx_drop, "tx_drop": tx_drop}]
        print(tabulate(output, headers='keys', tablefmt='fancy_grid'))
    else:
        print("%s:" % ig_name)
        output = [{"switch_name": switch_members['switch-name'], "interface_name": switch_members['interface-name'], "status": "interface down"}]
        print(tabulate(output, headers='keys', tablefmt='fancy_grid'))

def ig_check(ig_name):
    if cookie:
        session_cookie = 'session_cookie=%s' % cookie
        headers = {"content-type": "application/json", 'Cookie': session_cookie}
    else:
        print("I've just picked up a fault in the AE-35 unit.")
        sys.exit(1)
    if ig_name == '?':
        sorted_ig = list_all_ig()
        print("Use one of these interface groups:")
        for i in sorted_ig:
            print(i)
        kill_session()
        sys.exit(1)
    elif ig_name == '_all_':
        sorted_ig = list_all_ig()
        for i in sorted_ig:
            path = '/api/v1/data/controller/applications/bcf/info/fabric/interface-group/detail[name="%s"]' % i
            members = requests.get('https://' + base_url + path, headers=headers, verify=False).json()
            ig_lookup(i, members)
    else:
        path = '/api/v1/data/controller/applications/bcf/info/fabric/interface-group/detail[name="%s"]' % ig_name
        members = requests.get('https://' + base_url + path, headers=headers, verify=False).json()
        if len(members) == 0:
            sorted_ig = list_all_ig()
            print("Use one of these interface groups:")
            for i in sorted_ig:
                print(i)
            kill_session()
            sys.exit(1)
        else:
            ig_lookup(ig_name, members)

def ig_lookup(ig_name, members):
    if cookie:
        session_cookie = 'session_cookie=%s' % cookie
        headers = {"content-type": "application/json", 'Cookie': session_cookie}
    for x in members:
        for y in x['interface']:
            switch_name = y['member-info']['switch-name']
            path = '/api/v1/data/controller/core/switch[name="%s"]?select=dpid' % switch_name
            r_dpid = requests.get('https://' + base_url + path, headers=headers, verify=False).json()
            dpid = r_dpid[0]['dpid']
            y['member-info']['dpid'] = dpid
            switch_members = y['member-info']
            get_stats(switch_members, ig_name)

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
    ig_check(args.interface_group_name)
    kill_session()
