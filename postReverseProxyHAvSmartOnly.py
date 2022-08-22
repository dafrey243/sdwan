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

        if len(sys.argv) == 5:
            UUID = sys.argv[1]
            deviceIp = sys.argv[2]
            proxyIp = sys.argv[3]
            proxyIp2 = sys.argv[4]
        else:
            print("Four arguments required. 1) UUID of vManage or vSmart 2) IP of Device 3) IP of proxy 4) IP of Proxy2\n")
            exit()

        # PUT
        api_url = "/settings/configuration/reverseproxy"
        url = base_url + api_url
        payload = {"mode": "on"}
        response = requests.put(url=url, headers=headers,
                                data=json.dumps(payload), verify=False)
        if response.status_code == 200:
            print(response.status_code)
            print(response.url)
            print(response.text)
        else:
            if logger is not None:
                logger.error(str(response.text))

        time.sleep(5)

        # POST
        apilist = ["/system/reverseproxy/" + UUID]
        for api_url in apilist:
            url = base_url + api_url
            payload = [
                {
                    "privateIp": deviceIp,
                    "privatePort": 23456,
                    "proxyIp": proxyIp,
                    "proxyPort": 23456
                },
                {
                    "privateIp": deviceIp,
                    "privatePort": 23456,
                    "proxyIp": proxyIp2,
                    "proxyPort": 23456
                },
                {
                    "privateIp": deviceIp,
                    "privatePort": 23556,
                    "proxyIp": proxyIp,
                    "proxyPort": 23556
                },
                {
                    "privateIp": deviceIp,
                    "privatePort": 23556,
                    "proxyIp": proxyIp2,
                    "proxyPort": 23556
                }
            ]

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
