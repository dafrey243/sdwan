import datetime
from listToString import listToString
from prettytable import PrettyTable
import requests
import sys
import tabulate
import re
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



# Post AppRoute definition to vSmart
        api_url = "/template/policy/vsmart"
        url = base_url + api_url

        response = requests.get(
            url=url, headers=headers, verify=False)
        if response.status_code == 200:
            mydict = json.loads(response.text)
            table = list()
            headerrow = list()
            pheaderrow = list()
            # Creates the header row.  camelHump and/or dash will be multiline cell
            for item in mydict["data"][0:1]:
                for k, v in item.items():
                    # Take out keys when header row is too long
                    # Iterate over headerrow, and use pheaderrow for printing
                    if re.search("^(?!vdevice-dataKey|policyDefinition|createdBy|lastUpdatedBy|createdOn|@rid|policyVersion)", k):
                        headerrow.append(k)
                        # Replace dash with newline to make multicell headerrow
                        k = k.replace("-", "\n")
                        # Add newline at each capital letter in camelHump syntax
                        k = re.sub("([A-Z])", '\n' r'\1', k)
                        pheaderrow.append(k)

            # Iterate of data to create row.  Boundry of a row defined by headerrow (keys)
            for item in mydict["data"]:
                row = list()
                for item1 in headerrow:
                    var = item.get(item1)
                    if item1 == 'lastUpdatedOn':
                        lastupdated = item.get('lastUpdatedOn')
                        lastupdated = lastupdated / 1000
                        var = datetime.datetime.fromtimestamp(lastupdated)
                    if item1 == 'policyId':
                        policyId = item.get('policyId')
                    if var is None:
                        var = 'None'
                    row.append(var)
                table.append(row)

            try:
                print(url)
                print(tabulate.tabulate(table, pheaderrow, tablefmt="pretty"))
            except UnicodeEncodeError:
                print(tabulate.tabulate(table, headerrow, tablefmt="grid"))


        else:
            if logger is not None:
                logger.error(str(response.text))
# Post Activate policy on vSmart
        api_url = "/template/policy/vsmart/activate/" + policyId + "?confirm=true"
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
