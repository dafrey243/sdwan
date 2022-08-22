import datetime
from prettytable import PrettyTable
import requests
import sys
import tabulate
import json
import re
import time
import logging
import yaml
import os
import disable_https_warning
from authentication import Authentication
from mylogger import get_logger
from logging.handlers import TimedRotatingFileHandler
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings()

if __name__ == '__main__':

    try:
        print("\n")
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

        os.system('python getNetworkDesignProfileID.py') 
        templateId = raw_input('Enter template ID of device: ')

        api_url = "/template/device/config/attached/" + templateId
        url = base_url + api_url
        print(url)
        response = requests.get(url=url, headers=headers, verify=False)
        print(response.status_code)

        if response.status_code == 200:
            x = PrettyTable()

            mydata = json.loads(response.text)
#            print(json.dumps(mydata, indent=4))
            mydict = json.loads(response.text)
            for item in mydict["data"]:
                hostName = item['host-name']
                deviceIP = item['deviceIP']
                uuid = item['uuid']
                personality = item['personality']
                x.add_row([hostName, deviceIP, uuid, personality])
            print(x)

        else:
            if logger is not None:
                logger.error(str(response.text))


# Detach template and make CLI mode
        api_url = "/template/config/device/mode/cli"
        url = base_url + api_url
        print(url)
        payload = {"deviceType":personality,"devices":[{"deviceId":uuid,"deviceIP":hostName}]}
        response = requests.post(url=url, data=json.dumps(payload), headers=headers, verify=False)
        if response.status_code == 200:
            #mydata = json.loads(response.text)
            #print json.dumps(mydata, indent=4)
            print(response.status_code)
        else:
            print(response.status_code)

    except Exception as e:
        print('Exception line number: {}'.format(
            sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
