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

        with open("approute.yaml") as f:
            config = yaml.safe_load(f.read())
        siteListName = config["siteListName"]
        siteList = config["siteListData"]
        vpnListName = config["vpnListName"]
        vpnList = config["vpnListData"]
        centralPolicyName = config["centralPolicyName"]
        appRouteName = config["appRouteName"]
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
            name = 'None'
            for item in mydict["data"]:
                listId = item.get("listId")
                name = item.get("name")
                siteLists = listId
            if siteListName in name:
                print("siteLists: ") + siteLists
                print("site list " + name +
                      " already exists with ID ") + siteLists
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
            name = 'None'
            for item in mydict["data"]:
                listId = item.get("listId")
                name = item.get("name")
                if name is None:
                    name = "None"

                vpnLists = listId
            if vpnListName in name:
                print("vpnLists: ") + vpnLists
                print("vpn list " + name + " already exists with ID ") + vpnLists
# Else create vpn lists if it does not exist.
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
# App Probe Class
        api_url = "/template/policy/list/appprobe"
        url = base_url + api_url
        null = "null"
        payload = [
{"name":"EF","type":"appProbe","entries":[{"map":[{"color":"mpls","dscp":46}],"forwardingClass":"EF"}]},
{"name":"AF4","type":"appProbe","entries":[{"map":[{"color":"mpls","dscp":32}],"forwardingClass":"AF4"}]},
{"name":"AF3","type":"appProbe","entries":[{"map":[{"color":"mpls","dscp":24}],"forwardingClass":"AF3"}]},
{"name":"AF2","type":"appProbe","entries":[{"map":[{"color":"mpls","dscp":16}],"forwardingClass":"AF2"}]},
{"name":"AF1","type":"appProbe","entries":[{"map":[{"color":"mpls","dscp":8}],"forwardingClass":"AF1"}]},
{"name":"BE","type":"appProbe","entries":[{"map":[{"color":"mpls","dscp":0}],"forwardingClass":"BE"}]}]
        payload = payload.split(",")
        for line in payload:
            response = requests.post(url=url, headers=headers, data=json.dumps(line), verify=False)
            if response.status_code == 200:
                print(response.status_code)
                print(response.url)
                print(response.text)
        else:
            if logger is not None:
                logger.error(str(response.text))

# Get listIDs for the app Proble Class
        api_url = "/template/policy/list/appprobe"
        url = base_url + api_url
        response = requests.get(url=url, headers=headers, verify=False)
        if response.status_code == 200:
            mydata = json.loads(response.text)
        #    print(json.dumps(mydata, indent=4))
            mydict = json.loads(response.text)
            x = PrettyTable()
            x.field_names = ['listId', 'App Probe name']
            for item in mydict["data"]:
                listId = item["listId"]
                name = item["name"]
                x.add_row([listId, name])
                if name in "EF":
                    EFid = listId
                if name in "AF4id":
                    AF4id = listId
                if name in "AF3":
                    AF3id = listId
                if name in "AF2":
                    AF2id = listId
                if name in "AF1":
                    AF1id = listId
                if name in "BE":
                    BEid = listId
        else:
            if logger is not None:
                logger.error(str(response.text))


# Update existing default IPSLA with App probe IDs.

        api_url = "/template/policy/list/sla"
        url = base_url + api_url
        response = requests.get(url=url, headers=headers, verify=False)
        if response.status_code == 200:
            mydata = json.loads(response.text)
        #    print(json.dumps(mydata, indent=4))
            mydict = json.loads(response.text)
            x = PrettyTable()
            y = PrettyTable()
            sladict = {}
            for item in mydict["data"]:
                x.field_names = ['listId', 'name', 'description', 'type', 'jitter', 'latency', 'loss']
                listId = item["listId"]
                name = item["name"]
                ptype = item["type"]
                jitter = item["entries"][0]['jitter']
                latency = item["entries"][0]['latency']
                loss = item["entries"][0]['loss']
                x.add_row([listId, name, ptype, jitter, latency, loss])
                if name in "Realtime":
                    Realtime = listId
                    description = description
                    appProbeClass = EFid
                    sladict.update({name: Realtime, "jitter": jitter, "lo})
                if name in "Business-Critical":
                    Business_Critical = listId
                    description = description
                    appProbeClass = AF4id
                    sladict.update({name: Business_Critical})
                if name in "Transactional-Data":
                    Transactional_Data = listId
                    description = description
                    appProbeClass = AF3id
                    sladict.update({name: Transactional_Data})
                if name in "Best-Effort":
                    Best_Effort = listId
                    description = description
                    appProbeClass = BEid
                    sladict.update({name: Best_Effort})
            print(x)
        else:
            if logger is not None:
                logger.error(str(response.text))

#                 payload = {"name":name,"description":description,"type":"sla","entries":[{"latency":latency,"loss":loss,"jitter":jitter,"appProbeClass":appProbeClass}],"infoTag":""}

# API to get list ID for SLA class
        for slaname, slaid in sladict.items():
            api_url = "/template/policy/list/sla/" + slaid
                if slaname in "Realtime":
                    Realtime = listId
                    description = description
                    appProbeClass = EFid
                if slaname in "Business-Critical":
                    Business_Critical = listId
                    description = description
                    appProbeClass = AF4id
                if slaname in "Transactional-Data":
                    Transactional_Data = listId
                    description = description
                    appProbeClass = AF3id
                if slaname in "Best-Effort":
                    Best_Effort = listId
                    description = description
                    appProbeClass = BEid

                    payload = {"name":name,"description":description,"type":"sla","entries":[{"latency":latency,"loss":loss,"jitter":jitter,"appProbeClass":appProbeClass}],"infoTag":""}

            url = base_url + api_url
            response = requests.put(url=url, data=json.dumps(payload), headers=headers, verify=False)
            if response.status_code == 200:
                mydata = json.loads(response.text)
                    if name in "Realtime":
                        Realtime = listId
                        description = description
                        appProbeClass = EFid
                    if name in "Business-Critical":
                        Business_Critical = listId
                        description = description
                        appProbeClass = AF4id
                    if name in "Transactional-Data":
                        Transactional_Data = listId
                        description = description
                        appProbeClass = AF3id
                    if name in "Best-Effort":
                        Best_Effort = listId
                        description = description
                        appProbeClass = BEid
    
                    payload = {"name":name,"description":description,"type":"sla","entries":[{"latency":latency,"loss":loss,"jitter":jitter,"appProbeClass":appProbeClass}],"infoTag":""}
    
    
                print(x)
            else:
                if logger is not None:
                    logger.error(str(response.text))

# Post AppRoute definition
        api_url = "/template/policy/definition/approute"
        url = base_url + api_url
        null = "null"
        payload = {"name": appRouteName, "type": "appRoute", "description": appRouteName, "sequences": [{"sequenceId": 1, "sequenceName": "App Route", "sequenceType": "appRoute", "sequenceIpType": "ipv4", "match": {"entries": [{"field": "dscp", "value": "46"}]}, "actions": [{"type": "slaClass", "parameter": [{"field": "name", "ref": Realtime}, {"field": "preferredColor", "value": "mpls private1"}]}, {"type": "backupSlaPreferredColor", "parameter": "biz-internet public-internet"}]}, {"sequenceId": 11, "sequenceName": "App Route", "sequenceType": "appRoute", "sequenceIpType": "ipv4", "match": {"entries": [{"field": "dscp", "value": "32"}]}, "actions": [{"type": "slaClass", "parameter": [{"field": "name", "ref": Business_Critical}, {"field": "preferredColor", "value": "mpls private1"}]}, {"type": "backupSlaPreferredColor", "parameter": "biz-internet public-internet"}]}, {"sequenceId": 21, "sequenceName": "App Route", "sequenceType": "appRoute", "sequenceIpType": "ipv4", "match": {"entries": [{"field": "dscp", "value": "24"}]}, "actions": [{"type": "slaClass", "parameter": [{"field": "name", "ref": Business_Critical}, {"field": "preferredColor", "value": "mpls private1"}]}, {"type": "backupSlaPreferredColor", "parameter": "biz-internet public-internet"}]}, {"sequenceId": 31, "sequenceName": "App Route", "sequenceType": "appRoute", "sequenceIpType": "ipv4", "match": {"entries": [
            {"field": "dscp", "value": "16"}]}, "actions": [{"type": "slaClass", "parameter": [{"field": "name", "ref": Transactional_Data}, {"field": "preferredColor", "value": "biz-internet public-internet"}]}, {"type": "backupSlaPreferredColor", "parameter": "mpls private1"}]}, {"sequenceId": 41, "sequenceName": "App Route", "sequenceType": "appRoute", "sequenceIpType": "ipv4", "match": {"entries": [{"field": "dscp", "value": "8"}]}, "actions": [{"type": "slaClass", "parameter": [{"field": "name", "ref": Transactional_Data}, {"field": "preferredColor", "value": "biz-internet public-internet"}]}, {"type": "backupSlaPreferredColor", "parameter": "mpls private1"}]}, {"sequenceId": 51, "sequenceName": "App Route", "sequenceType": "appRoute", "sequenceIpType": "ipv4", "match": {"entries": [{"field": "dscp", "value": "4"}]}, "actions": [{"type": "slaClass", "parameter": [{"field": "name", "ref": Best_Effort}, {"field": "preferredColor", "value": "biz-internet public-internet"}, {"field": "strict"}]}]}, {"sequenceId": 61, "sequenceName": "App Route", "sequenceType": "appRoute", "sequenceIpType": "ipv4", "match": {"entries": [{"field": "dscp", "value": "0"}]}, "actions": [{"type": "slaClass", "parameter": [{"field": "name", "ref": Best_Effort}, {"field": "preferredColor", "value": "biz-internet public-internet"}]}, {"type": "backupSlaPreferredColor", "parameter": "mpls private1"}]}]}

        response = requests.post(
            url=url, headers=headers, data=json.dumps(payload), verify=False)
        if response.status_code == 200:
            print(response.status_code)
            print(response.url)
            print(response.text)
            json_data = json.loads(response.text)
            key, val = json_data.items()[0]
            appRouteDefId = str(val)
            print("approuteid = ") + appRouteDefId
        else:
            if logger is not None:
                logger.error(str(response.text))

# Post AppRoute definition to vSmart
        api_url = "/template/policy/vsmart"
        url = base_url + api_url
        payload = {"policyDescription": centralPolicyName, "policyType": "feature", "policyName": centralPolicyName, "policyDefinition": {"assembly": [
            {"definitionId": appRouteDefId, "type": "appRoute", "entries": [{"siteLists": [siteLists], "vpnLists":[vpnLists]}]}]}, "isPolicyActivated": False}

        #payload.replace(":true,", ":True,").replace(":false,", ":False,")

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
