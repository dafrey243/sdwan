from listToString import listToString
from prettytable import PrettyTable
import requests
import sys
import json
import time
import logging
import yaml
import os
import disable_https_warning
import approute
from authentication import Authentication
from mylogger import get_logger
from logging.handlers import TimedRotatingFileHandler
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings()

if __name__ == '__main__':

    try:
#        os.system('clear')
        print("\n\n")
        mainfile = os.path.basename(__file__)
        log_level = logging.DEBUG
        logger = get_logger("log/apilog.txt", log_level)
        if logger is not None:
            logger.info("Loading vManage login details from YAML\n")
        with open("vmanage_login.yaml") as f:
            config = yaml.safe_load(f.read())

        vmanage_host = config["vmanage_host"]
        vmanage_port = config["vmanage_port"]
        username = config["vmanage_username"]
        password = config["vmanage_password"]

        Auth = Authentication()
        jsessionid = Auth.get_jsessionid(
            vmanage_host, vmanage_port, username, password)
        token = Auth.get_token(vmanage_host, vmanage_port, jsessionid)

        if token is not None:
            headers = {'Content-Type': "application/json",
                       'Cookie': jsessionid, 'X-XSRF-TOKEN': token}
        else:
            headers = {'Content-Type': "application/json",
                       'Cookie': jsessionid}

        base_url = "https://%s:%s/dataservice" % (vmanage_host, vmanage_port)
# Site List
        api_url = "/template/policy/list/site"
        url = base_url + api_url
	null = "null"
	payload = {"name": "all", "description": "Desc Not Required",
	    "type": "site", "listId": null, "entries": [{"siteId": "1-999999"}]}
        response = requests.post(
            url=url, headers=headers, data=json.dumps(payload), verify=False)
        if response.status_code == 200:
            print(response.status_code)
            print(response.url)
            print(response.text)
        else:
            if logger is not None:
                logger.error(str(response.text))

# VPN List
        api_url = "/template/policy/list/vpn"
        url = base_url + api_url
        null = "null"
        payload = {"name": "vpn1", "description": "Desc Not Required",
            "type": "vpn", "listId": null, "entries": [{"vpn": "1"}]}
        response = requests.post(
            url=url, headers=headers, data=json.dumps(payload), verify=False)
        if response.status_code == 200:
            print(response.status_code)
            print(response.url)
            print(response.text)
        else:
            if logger is not None:
                logger.error(str(response.text))

# Using Default SLA classes so not creating new.

# Create Application sequence

        api_url = "/template/policy/definition/approute"
        url = base_url + api_url
        null = "null"
        seq = list()
# Set up list of sequences for app route
	with open("approute.yaml") as f:
            config = yaml.safe_load(f.read())
	seq = ["sequence1", "sequence11", "sequence21",
	    "sequence31", "sequence41", "sequence51", "sequence61"]
        payload = {"name": "myapproute", "type": "appRoute",
            "description": "myapproute", "sequences": []}

	for item in seq:
	    sequence = config["sequences"][item]["sequence"]
	    ref = config["sequences"][item]["ref"]
            dscp = config["sequences"][item]["dscp"]
	    pref = config["sequences"][item]["pref"]
	    backup = config["sequences"][item]["backup"]
# API to get list ID for SLA class

            api_url = "/template/policy/list/sla"
            url = base_url + api_url
            response = requests.get(url=url, headers=headers, verify=False)
            if response.status_code == 200:
                mydata = json.loads(response.text)
            #    print(json.dumps(mydata, indent=4))
                mydict = json.loads(response.text)
                x = PrettyTable()
                y = PrettyTable()
                for item in mydict["data"]:
                    x.field_names = ['listId', 'name',
                                     'type', 'jitter', 'latency', 'loss']
                    listId = item["listId"]
                    name = item["name"]
# Get listIds of SLA classes for policy and stuff into dictionary
		   if name in ('Realtime', 'Business-Critical', 'Transactional-Data', 'Best-Effort'):
			myDict["Name"].append(name)
		        myDict["ref"].append(listId)
                    ptype = item["type"]
                    jitter = item["entries"][0]['jitter']
                    latency = item["entries"][0]['latency']
                    loss = item["entries"][0]['loss']
                    x.add_row([listId, name, ptype, jitter, latency, loss])
	            print("sequence: ") + sequence 
        	    print("ref: ") + ref 
            	    print("dscp ") + dscp 
            	    print("prefer: ") + pref 
            	    print("backup: ") + backup
                print( x)
            else:
                if logger is not None:
                    logger.error(str(response.text))

	payload = {"name":"myapproute","type":"appRoute","description":"myapproute","sequences":[    
]}


            mplsDict = {"sequenceId":sequence,"sequenceName":"App Route","sequenceType":"appRoute","sequenceIpType":"ipv4","match":{"entries":[{"field":"dscp","value":dscp}]},"actions":[{"type":"slaClass","parameter":[{"field":"name","ref":listId},{"field":"preferredColor","value":pref}]},{"type":"backupSlaPreferredColor","parameter":backup}]}





    except Exception as e:
        print('Exception line number: {}'.format(
            sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
