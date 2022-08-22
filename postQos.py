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
# Does  sitelist name already exist?
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
                siteLists = listId
            if siteListName in name:
                print("siteLists: ") + siteLists
                print("site list " + name +
                      " already exists with ID ") + siteLists
# Create site lists if it does not exist.
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
# Does vpn list name already exist?
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
                vpnLists = listId
            if vpnListName in name:
                print("vpnLists: ") + vpnLists
                print("vpn list " + name + " already exists with ID ") + vpnLists
# Create vpn lists if it does not exist.
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

        response = requests.post(
            url=url, headers=headers, data=json.dumps(payload), verify=False)
        if response.status_code == 200:
            print(response.status_code)
            print(response.url)
            print(response.text)
            json_data = json.loads(response.text)
            key, val = json_data.items()[0]
            defId = str(val)
            print("defId = ") + defId
            print(
                "QoS definition posted.  Add to existing central policy or create new in vManage UI")
        else:
            if logger is not None:
                logger.error(str(response.text))

    except Exception as e:
        print('Exception line number: {}'.format(
            sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
