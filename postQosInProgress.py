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
# Yaml file with parameter settings.

        with open("qos.yaml") as f:
            config = yaml.safe_load(f.read())
	siteListName = config["siteListName"]
	siteList = config["siteListData"]
	vpnListName = config["vpnListName"]
	vpnList = config["vpnListData"]
	centralPolicyName = config["centralPolicyName"]
	defName = config["defName"]
	Realtime = config["Realtime"]
	BusinessCritical = config["BusinessCritical"]
        TransactionalData = config["TransactionalData"]
        BestEffort = config["BestEffort"]


# Site List
# Does your sitelist name already exist?
	api_url = "/template/policy/list/site"
        url = base_url + api_url
        response = requests.get(url=url, headers=headers, verify=False)
        if response.status_code == 200:
            mydata = json.loads(response.text)
        #    print(json.dumps(mydata, indent=4))
            mydict = json.loads(response.text)
            for item in mydict["data"]:
                listId = item["listId"]
                name = item["name"]
		if name in siteListName:
		    siteLists = listId
		    print("siteLists: ") + siteLists
# Else create site lists if it does not exist.
		else:
                    api_url = "/template/policy/list/site"
                    url = base_url + api_url
                    null = "null"
                    payload = {"name": siteListName, "description": "Desc Not Required",
                        "type": "site", "listId": null, "entries": [{"siteId": siteList}]}
                    response = requests.post(
                        url=url, headers=headers, data=json.dumps(payload), verify=False)
                    if response.status_code == 200:
                        print(response.status_code)
                        print(response.url)
                        print(response.text)
                        json_data = json.loads(response.text)
                        key, val = json_data.items()[0]
                        siteLists = str(val)
                        print("siteLists = ") + siteLists
                    else:
                        if logger is not None:
                            logger.error(str(response.text))
        else:
            if logger is not None:
                logger.error(str(response.text))
# Does your vpn list name already exist?
        api_url = "/template/policy/list/vpn"
        url = base_url + api_url
        response = requests.get(url=url, headers=headers, verify=False)
        if response.status_code == 200:
            mydata = json.loads(response.text)
        #    print(json.dumps(mydata, indent=4))
            mydict = json.loads(response.text)
            for item in mydict["data"]:
                listId = item["listId"]
                name = item["name"]
                if name in vpnListName:
                    vpnLists = listId
                    print("vpnLists: ") + vpnLists
# Else create site lists if it does not exist.
                else:
                    api_url = "/template/policy/list/vpn"
                    url = base_url + api_url
                    null = "null"
                    payload = {"name": vpnListName, "description": "Desc Not Required",
                        "type": "vpn", "listId": null, "entries": [{"vpn": vpnList}]}
                    response = requests.post(
                        url=url, headers=headers, data=json.dumps(payload), verify=False)
                    if response.status_code == 200:
                        print(response.status_code)
                        print(response.url)
                        print(response.text)
                        json_data = json.loads(response.text)
                        key, val = json_data.items()[0]
                        vpnLists = str(val)
                        print("vpnLists = ") + vpnLists

                    else:
                        if logger is not None:
                            logger.error(str(response.text))

# Post QoS
        api_url = "/template/policy/definition/data"
        url = base_url + api_url
        null = "null"
	payload = {"name": defName, "type": "data", "description": defName, "defaultAction": {"type": "drop"}, "sequences": [{"sequenceId": 1, "sequenceName": "QoS", "baseAction": "accept", "sequenceType": "qos", "sequenceIpType": "ipv4", "match": {"entries": [{"field": "dscp", "value": "46"}]}, "actions": [{"type": "set", "parameter": [{"field": "forwardingClass", "value": "Realtime"}]}]}, {"sequenceId": 11, "sequenceName": "QoS", "baseAction": "accept", "sequenceType": "qos", "sequenceIpType": "ipv4", "match": {"entries": [{"field": "dscp", "value": "32"}]}, "actions": [{"type": "set", "parameter": [{"field": "forwardingClass", "value": "Priority"}]}]}, {"sequenceId": 21, "sequenceName": "QoS", "baseAction": "accept", "sequenceType": "qos", "sequenceIpType": "ipv4", "match": {"entries": [{"field": "dscp", "value": "24"}]}, "actions": [{"type": "set", "parameter": [{"field": "forwardingClass", "value": "MissionCritical"}]}]}, {"sequenceId": 31, "sequenceName": "QoS", "baseAction": "accept", "sequenceType": "qos", "sequenceIpType": "ipv4", "match": {
	    "entries": [{"field": "dscp", "value": "16"}]}, "actions": [{"type": "set", "parameter": [{"field": "forwardingClass", "value": "Transactional"}]}]}, {"sequenceId": 41, "sequenceName": "QoS", "baseAction": "accept", "sequenceType": "qos", "sequenceIpType": "ipv4", "match": {"entries": [{"field": "dscp", "value": "8"}]}, "actions": [{"type": "set", "parameter": [{"field": "forwardingClass", "value": "General"}]}]}, {"sequenceId": 51, "sequenceName": "QoS", "baseAction": "accept", "sequenceType": "qos", "sequenceIpType": "ipv4", "match": {"entries": [{"field": "dscp", "value": "4"}]}, "actions": [{"type": "set", "parameter": [{"field": "forwardingClass", "value": "BestEffort"}]}]}, {"sequenceId": 61, "sequenceName": "QoS", "baseAction": "accept", "sequenceType": "qos", "sequenceIpType": "ipv4", "match": {"entries": [{"field": "dscp", "value": "0"}]}, "actions": [{"type": "set", "parameter": [{"field": "forwardingClass", "value": "BestEffort"}]}]}]}

	response = requests.post(url=url, headers=headers,
	                         data=json.dumps(payload), verify=False)
        if response.status_code == 200:
            print(response.status_code)
            print(response.url)
            print(response.text)
            json_data = json.loads(response.text)
            key, val = json_data.items()[0]
	    defId = str(val)
	    print("defId = ") + defId
        else:
            if logger is not None:
                logger.error(str(response.text))

# Same as App route here.  Make generic variable names below to be used on all central policies.
# Post QoS definition to vSmart
Is there an active central policy?   If so do the PUT method, if not then post
Request URL: https: // 192.168.0.56/dataservice/template/policy/vsmart/f6e0226a-fd7a-44c5-ac71-ddc53a01cb1e
Request Method: PUT
{"policyDescription": "Central_Policy", "policyType": "feature", "policyName": "Central_Policy", "policyDefinition": {"assembly": [{"definitionId": "c9bf7855-e2ec-406f-9bac-ca0429ebe21e", "type": "data", "entries": [{"direction": "all", "siteLists": ["0fca74cb-1009-4e95-963a-f2de92ddd4ba"], "vpnLists":[
    "e4097946-efd3-4df2-8340-39f6ab078626"]}]}, {"definitionId": "f2a45cbb-f504-41b8-8af3-71d1071a80ac", "type": "appRoute", "entries": [{"siteLists": ["b69da647-0242-42fe-b167-105b9ad43ae7"], "vpnLists":["e4097946-efd3-4df2-8340-39f6ab078626"]}]}]}, "isPolicyActivated": true}

      "policyDefinition": "{\"assembly\":[{\"definitionId\":\"f2a45cbb-f504-41b8-8af3-71d1071a80ac\",\"type\":\"appRoute\",\"entries\":[{\"siteLists\":[\"b69da647-0242-42fe-b167-105b9ad43ae7\"],\"vpnLists\":[\"e4097946-efd3-4df2-8340-39f6ab078626\"]}]}]}",

# Central policy already active?
        api_url = "/template/policy/vsmart"
        url = base_url + api_url
        response = requests.get(url=url, headers=headers, verify=False)
        if response.status_code == 200:
            mydata = json.loads(response.text)
        #    print(json.dumps(mydata, indent=4))
            mydict = json.loads(response.text)
            for item in mydict["data"]:
		policyName = item["policyName"]
		isPolicyActivated = item["isPolicyActivated"]
		policyId = item["policyId"]
                if isPolicyActivated == true:
	            api_url = "/template/policy/vsmart"
                    url = base_url + api_url
		    payload = {"policyDescription": policyName, "policyType": "feature", "policyName": policyName, "policyDefinition": {"assembly": [{"definitionId": defId, "type": "data", "entries": [{"direction": "all", "siteLists": [siteLists], "vpnLists":[
		        vpnLists]}]}, {"definitionId": "f2a45cbb-f504-41b8-8af3-71d1071a80ac", "type": "appRoute", "entries": [{"siteLists": ["b69da647-0242-42fe-b167-105b9ad43ae7"], "vpnLists":["e4097946-efd3-4df2-8340-39f6ab078626"]}]}]}, "isPolicyActivated": true}


# Else create site lists if it does not exist.
                else:

        api_url = "/template/policy/vsmart"
        url = base_url + api_url
        payload = {"policyDescription": centralPolicyName, "policyType": "feature", "policyName": centralPolicyName, "policyDefinition": {
            "assembly": [{"definitionId": defId, "type": "data", "entries": [{"direction": "service", "siteLists": [siteLists], "vpnLists":[vpnLists]}]}]}}
# ,"isPolicyActivated":false}
        response = requests.post(
            url=url, headers=headers, data=json.dumps(payload), verify=False)
        if response.status_code == 200:
            print(response.status_code)
            print(response.url)
            print(response.text)
	    json_data = json.loads(response.text)
	    key, val = json_data.items()[0]
            centralPolicy = str(val)
	    print("centralP = ") + centralPolicy
        else:
            if logger is not None:
                logger.error(str(response.text))
# Post Activate policy on vSmart
Request URL: https: // 192.168.0.56/dataservice/template/policy/vsmart/activate/f6e0226a-fd7a-44c5-ac71-ddc53a01cb1e?confirm = true
Request Method: POST
{"isEdited": true}

        api_url = "/template/policy/vsmart/activate/" + centralPolicy + "?confirm=true"
        url = base_url + api_url
	payload = {}
        response = requests.post(
            url=url, headers=headers, data=json.dumps(payload), verify=False)
        if response.status_code == 200:
            print(response.status_code)
            print(response.url)
            print(response.text)
        else:
            if logger is not None:
                logger.error(str(response.text))

    except Exception as e:
        print('Exception line number: {}'.format(
            sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
