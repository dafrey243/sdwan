#!/usr/bin/python

import requests
import urllib3
import sys
import json
import pdb
import os
from collections import OrderedDict

if len(sys.argv) == 2:
        SYSTEM_IP = sys.argv[1]
        #print "SYSTEM_IP = ", SYSTEM_IP, "\n"
#        SYSTEM_IP = SYSTEM_IP.replace('/', '%2F')
#        print "SYSTEM_IP = ", SYSTEM_IP, "\n"
else:
        COMMAND_NAME =  os.path.basename(sys.argv[0])
        print ""
        print "Command: ", COMMAND_NAME, " <SYSTEM_IP>\n"
        exit()

import controller_data
controller_ip = controller_data.default_controller["controller_ip"]
controller_username = controller_data.default_controller["controller_username"]
controller_password = controller_data.default_controller["controller_password"]

sys.tracebacklimit = 0

#print "Controller IP:       ",controller_ip
#print "Controller Username: ",controller_username
#print "Controller Password: ",controller_password

login_url = 'https://' + controller_ip + ':8443'
username = controller_username
password = controller_password
headers = {'Content-Type': 'application/x-www-form-urlencoded'}
HOSTNAME = ''

#print "login_url: ",login_url

urllib3.disable_warnings()
s = requests.Session()

login_action = '/j_security_check'
url = login_url + login_action
payload = {'j_username' : username, 'j_password' : password}
response = s.post(url, data=payload, headers=headers, verify=False, allow_redirects=False)
#print(response.url)
#print(response.status_code)
#print(response.text)

if response.status_code != 200:
        print "Unable to communicate with vManage or pass login authenticate!!!"
        print "HTTP Code: ", response.status_code, "\n"
        exit()

login_action = '/dataservice/client/token'
url = login_url + login_action
headers = {'Content-Type' : 'application/json', 'Accept' : 'application/json'}
response = s.get(url, headers=headers, verify=False)

if response.status_code == 200:
        csrf = (response.text)
        ##print "csrf = ", csrf
else:
        print "Unable to retrieve csrf token ...\n"
        print "HTTP Code: ", response.status_code, "\n"

login_action = '/dataservice/device/cloudx/applications?deviceId=%s&&' % SYSTEM_IP
url = login_url + login_action
headers = {'Content-Type' : 'application/json', 'Accept' : 'application/json', 'X-XSRF-TOKEN' : csrf }
response = s.get(url, headers=headers, verify=False)
#print(response.url)
#print(response.status_code)
#print(response.headers)

if response.status_code == 200:

	mydata = json.loads(response.text)
	print json.dumps(mydata, indent=4)


else:
        mydata = json.loads(response.text)
#       print json.dumps(mydata, indent=4)
        print ""
        print "HTTP Code:     ", response.status_code
        print "ERROR MESSAGE: ", mydata['error']['message']
        print "ERROR DETAILS: ", mydata['error']['details']

