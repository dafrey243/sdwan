#!/usr/bin/python

import requests
import urllib3
import sys
import json
import pdb
import os
import controller_data
from collections import OrderedDict

controller_ip = controller_data.vManage["controller_ip"]
controller_username = controller_data.vManage["controller_username"]
controller_password = controller_data.vManage["controller_password"]

sys.tracebacklimit = 0

login_url = 'https://' + controller_ip + ':443'
username = controller_username
password = controller_password
headers = {'Content-Type': 'application/x-www-form-urlencoded'}


if len(sys.argv) == 2:
	FILENAME = sys.argv[1]
        print "\nFilename: ", FILENAME


#if os.path.isfile(FILENAME):
#        print "Reading file: ", FILENAME
#else:
#        print "File doesn't exist!!!: ", FILENAME
#        exit()

urllib3.disable_warnings()

s = requests.Session()
login_action = '/j_security_check'
headers = {'Content-Type': 'application/x-www-form-urlencoded'}
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

myfilename = FILENAME

directory = 'templates/vSmartft/'

if not os.path.isdir(directory):
    print "Directory is not present"
    exit()

myfilename = os.path.join(directory, myfilename)         

payload  = (json.load(open(myfilename,"r")))
print(payload)

login_action = '/dataservice/template/feature'
url = login_url + login_action
headers = {'Content-Type' : 'application/json', 'Accept' : 'application/json', 'X-XSRF-TOKEN' : csrf }
response = s.post(url, data=json.dumps(payload), headers=headers, verify=False, allow_redirects=False)

#print "data", data

print(response.url)
print(response.status_code)
#print(payload)
#print(response.text)

if response.status_code == 200:
	print "Template successfully uploaded: ", FILENAME, "\n"
else:
	mydata = json.loads(response.text)
	print json.dumps(mydata, indent=4)
	print ""
	print "HTTP Code:     ", response.status_code
	print "ERROR MESSAGE: ", mydata['error']['message']
	print "ERROR DETAILS: ", mydata['error']['details']
