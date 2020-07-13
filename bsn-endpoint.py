#!/usr/bin/env python3
import re
import argparse
import os
import sys
import requests
from pygments import highlight
from pygments.lexers import JsonLexer
from pygments.formatters import TerminalFormatter

requests.packages.urllib3.disable_warnings()
username = os.getenv('BSNUSER')
password = os.environ.get('BSNPASS')
p_name = os.path.basename(sys.argv[0])
parser = argparse.ArgumentParser(description='BCF endpoint information')
parser.add_argument('controller', type=str, help='lab, dc01, dc02')
parser.add_argument('input', type=str, help='IPv4 address or endpoint name. example: 10.255.4.110 or nutanix-PCC-LAB-vm-50-6b-8d-ca-98-45')
parser.add_argument('-up', action='store_true', help="admin up endpoint")
parser.add_argument('-down', action='store_true', help="admin down endpoint")

args = parser.parse_args()
#print(args)

def display_error(error_message):
    print(error_message)
    print("[OPTION] lab (API call on lab controller)")
    print("[OPTION] dc01 (API call on dc01 controller)")
    print("[OPTION] dc02 (API call on dc02 controller)")
    print("example: %s lab 10.255.4.110" % p_name)
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

def ip_check(input_ip):
    ipv4_check = re.compile("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
    nutanix_name = re.compile("^nutanix-(.+-)?vm(-.{2}){6}$")
    if ipv4_check.match(input_ip):
        ip = input_ip
        is_ip = True
        endpoint_lookup(ip, is_ip)
    elif input_ip == '?':
        ip = input_ip
        is_ip = False
        endpoint_lookup(ip, is_ip)
    elif nutanix_name.match(input_ip):
        ip = input_ip
        is_ip = False
        endpoint_lookup(ip, is_ip)
    else:
        error_message = "ERROR: not a valid IPv4 address"
        display_error(error_message)

def endpoint_lookup(ip, is_ip):
    if cookie:
        session_cookie = 'session_cookie=%s' % cookie
        headers = {"content-type": "application/json", 'Cookie': session_cookie}
        if ip == '?' and not is_ip:
            endpoint_list = []
            path = '/api/v1/data/controller/applications/bcf/info/endpoint-manager/endpoint'
            s = requests.get('https://' + base_url + path, headers=headers, verify=False).json()
            print("Use one of these endpoints:")
            for x in s:
                if all(key in x.keys() for key in ('name', 'ip-address')):
                    print("name: %s ip-address: %s" % (x['name'], x['ip-address'][0]['ip-address']))
                elif 'ip-address' in x.keys():
                    print("ip-address: %s" % x['ip-address'][0]['ip-address'])
            kill_session()
            sys.exit(1)
        elif ip and is_ip:
            path = '/api/v1/data/controller/applications/bcf/info/endpoint-manager/endpoint[ip="%s"]' % ip
            s = requests.get('https://' + base_url + path, headers=headers, verify=False)
            sjson = s.json()
            if s:
                iface_group = sjson[0]['interface-group']
                ip_addr = sjson[0]['ip-address'][0]['ip-address']
                tenant = sjson[0]['tenant']
                segment = sjson[0]['segment']
                state = sjson[0]['state']
                if 'name' in sjson[0].keys():
                    name = sjson[0]['name']
                else:
                    name = "<no static endpoint>"
                output = "name: %s\n    interface-group: %s\n    ip-address: %s\n    tenant: %s\n    segment: %s\n    state: %s" % (name, iface_group, ip_addr, tenant, segment, state)
                #output = "interface-group: %s\n    ip-address: %s\n    tenant: %s\n    segment: %s\n    state: %s" % (iface_group, ip_addr, tenant, segment, state)
                print(output)
#                print(highlight(s.text, JsonLexer(), TerminalFormatter()))
#                print(sjson[0].keys())
        elif ip and not is_ip:
            path = '/api/v1/data/controller/applications/bcf/info/endpoint-manager/endpoint[name="%s"]' % ip
            s = requests.get('https://' + base_url + path, headers=headers, verify=False)
            sjson = s.json()
            if s:
                iface_group = sjson[0]['interface-group']
                if 'ip-address' in sjson[0].keys():
                    ip_addr = sjson[0]['ip-address'][0]['ip-address']
                tenant = sjson[0]['tenant']
                segment = sjson[0]['segment']
                state = sjson[0]['state']
                if 'name' in sjson[0].keys():
                    name = sjson[0]['name']
                else:
                    name = ""
                try:
                    ip_addr
                except NameError:
                    output = "name: %s\n    interface-group: %s\n    tenant: %s\n    segment: %s\n    state: %s" % (name, iface_group, tenant, segment, state)
                else:
                    output = "name: %s\n    interface-group: %s\n    ip-address: %s\n    tenant: %s\n    segment: %s\n    state: %s" % (name, iface_group, ip_addr, tenant, segment, state)
                #output = "interface-group: %s\n    ip-address: %s\n    tenant: %s\n    segment: %s\n    state: %s" % (iface_group, ip_addr, tenant, segment, state)
                print(output)
        if args.up and name != "":
            shutdown = False
            endpoint_control(tenant, segment, name, shutdown)
        elif args.down and name != "":
            shutdown = True
            endpoint_control(tenant, segment, name, shutdown)
        elif args.up or args.down and name == "":
            print("No static endpoint for %s, create a static endpoint for %s first." % (ip_addr, ip_addr))
    else:
        print("I've just picked up a fault in the AE-35 unit.")
        sys.exit(1)

def endpoint_control(tenant, segment, name, shutdown):
    if cookie:
        session_cookie = 'session_cookie=%s' % cookie
        headers = {"content-type": "application/json", 'Cookie': session_cookie}
        if shutdown:
            path = '/api/v1/data/controller/applications/bcf/tenant[name="%s"]/segment[name="%s"]/endpoint[name="%s"]' % (tenant, segment, name)
            data = '{"shutdown": true}'
            s = requests.patch('https://' + base_url + path, headers=headers, data=data, verify=False)
            if s.status_code == 204:
                print()
                print("Success: endpoint %s is now admin down" % name)
                print()
        else:
            path = '/api/v1/data/controller/applications/bcf/tenant[name="%s"]/segment[name="%s"]/endpoint[name="%s"]/shutdown' % (tenant, segment, name)
            s = requests.delete('https://' + base_url + path, headers=headers, verify=False)
            if s.status_code == 204:
                print()
                print("Success: endpoint %s is now admin up" % name)
                print()
    else:
        print("I've just picked up a fault in the AE-35 unit.")
        sys.exit(1)

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
    ip_check(args.input)
    kill_session()
