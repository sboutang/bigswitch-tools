#!/usr/bin/env python3
import argparse
import os
import sys
import requests
import re

requests.packages.urllib3.disable_warnings()
username = os.getenv('BSNUSER')
password = os.getenv('BSNPASS')
p_name = os.path.basename(sys.argv[0])
parser = argparse.ArgumentParser(description='BCF build segment')
parser.add_argument('controller', type=str, help='lab, dc01, dc02')
args = parser.parse_args()
base_url = ''
cookie = ''

def clear():
     _ = (os.system('clear') if os.name =='posix' else os.system('cls'))

def display_error(error_message):
    print(error_message)
    print("[OPTION] lab")
    print("[OPTION] dc01")
    print("[OPTION] dc02")
    print("example: %s lab" % p_name)
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

def add_ntnx(vlan_id, tenant, segment):
    if cookie:
        session_cookie = 'session_cookie=%s' % cookie
        headers = {"content-type": "application/json", 'Cookie': session_cookie}
        ig_list = []
        path = '/api/v1/data/controller/applications/bcf/info/fabric/interface-group/summary'
        groups = requests.get('https://' + base_url + path, headers=headers, verify=False).json()
        nutanix_clusters = []
        path = '/api/v1/data/controller/applications/vendor/nutanix/prism-server'
        prism = requests.get('https://' + base_url + path, headers=headers, verify=False).json()
        ahv_regex = re.compile('^.+ahv.+')
        nutanix_regex = re.compile('^nutanix.+')
        for ig in groups:
            if nutanix_regex.match(ig['name']):
                ig.pop("name", None)
            elif ahv_regex.match(ig['name']):
                ig_list.append(ig['name'])
        sorted_ig = sorted(set(ig_list))
        for i in sorted_ig:
            print("    member interface-group %s vlan %s" % (i, vlan_id))
        for cluster in prism:
            print()
            print("nutanix-prism %s" % cluster['name'])
            print("  manage-segment-for-vlan vlan %s tenant %s segment %s" % (vlan_id, tenant, segment))
        kill_session()
    else:
        print("I've just picked up a fault in the AE-35 unit.")
        sys.exit(1)

def base(base_url):
    tenant = str(input("tenant name: "))
    segment = str(input("segment name: "))
    vlan_id = int(input("vlan id: "))
    l3_needed = str(input("configure L3 subnet for this segment: (y/n) "))
    if l3_needed =='y':
        l3_addrmask = str(input("address and mask in the form of x.x.x.x/xx: "))
        dhcp_needed = str(input("configure DHCP relay: (y/n) "))
    system_needed = str(input("connect to system tenant: (y/n) "))
    core_needed = str(input("add core L2 interface: (y/n) "))
    seg_needed = str(input("add seg-fw L2 interface: (y/n) "))
    f5_needed = str(input("add F5 L2 interface: (y/n) "))
    ntnx_needed = str(input("add to nutanix: (y/n) "))
    if base_url == 'mn-pcclab-pnet-ctlr:8443':
        corel2 = "mn-pcclab-core-sw-vpc17"
        fw1l2 = "mn-pcclab-eia-fw01-Internal-Seg-pri"
        fw2l2 = "mn-pcclab-eia-fw01-Internal-Seg-sec"
        f51l2 = "NO_LAB_F5"
        f52l2 = "NO_LAB_F5"
    elif base_url == 'dc01-bcf-ctrl:8443':
        corel2 = "dc01-7k-core-vpc70"
        fw1l2 = "dc01-intsegfw01-a-ae3"
        fw2l2 = "dc01-intsegfw01-b-ae3"
        f51l2 = "DOES_NOT_YET_EXIST"
        f52l2 = "DOES_NOT_YET_EXIST"
    elif base_url == 'dc02-bcf-ctrl:8443':
        corel2 = "dc02-n7k-vpc71"
        fw1l2 = "dc02-intsegfw01-a-ae2"
        fw2l2 = "dc02-intsegfw01-b-ae2"
        f51l2 = "dc02-lb-01a"
        f52l2 = "dc02-lb-01b"
    clear()
    print("----------")
    if system_needed == 'y':
        print("tenant system")
        print("  logical-router")
        print("      interface tenant %s" % tenant)
        print("      export-route")
    print("tenant %s" % tenant)
    if system_needed == 'y' and l3_needed == 'y':
        print("  logical-router")
        print("    route 0.0.0.0/0 next-hop tenant system")
        print("    interface tenant system")
        print("      import-route")
        print("    interface segment %s" % segment)
        print("      ip address %s" % l3_addrmask)
        if dhcp_needed == 'y':
            print("      dhcp-relay server-ip 172.16.241.8")
            print("      dhcp-relay server-ip 172.16.250.254")
    elif system_needed == 'n' and l3_needed == 'y':
        print("  logical-router")
        print("    interface segment %s" % segment)
        print("      ip address %s" % l3_addrmask)
        if dhcp_needed == 'y':
            print("      dhcp-relay server-ip 172.16.241.8")
            print("      dhcp-relay server-ip 172.16.250.254")
    elif system_needed == 'y' and l3_needed == 'n':
        print("  logical-router")
        print("    route 0.0.0.0/0 next-hop tenant system")
        print("    interface tenant system")
        print("      import-route")
    print("  segment %s" % segment)
    if core_needed == 'y':
        print("    member interface-group %s vlan %s" % (corel2, vlan_id))
    if seg_needed == 'y':
        print("    member interface-group %s vlan %s" % (fw1l2, vlan_id))
        print("    member interface-group %s vlan %s" % (fw2l2, vlan_id))
    if f5_needed == 'y':
        print("    member interface-group %s vlan %s" % (f51l2, vlan_id))
        print("    member interface-group %s vlan %s" % (f52l2, vlan_id))
    if ntnx_needed == 'y':
        add_ntnx(vlan_id, tenant, segment)
    kill_session()

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
    base(base_url)
    kill_session()
