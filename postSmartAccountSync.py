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

        if len(sys.argv) == 3:
            USERNAME = sys.argv[1]
            PASSWORD = sys.argv[2]
        else:
            print(
                "Two arguments required. 1) CCO username 'username@cisco.com' in single quotes.  2) CCO password to sync smart account in single quotes 'password'\n")
            exit()

        base_url = "https://%s:%s/dataservice" % (vmanage_host, vmanage_port)

# Post Smart Sync Account
        api_url = "/system/device/smartaccount/sync"
        url = base_url + api_url
        null = "null"
        payload = {"username": USERNAME,
                   "password": PASSWORD, "validity_string": "valid"}
        response = requests.post(url=url, headers=headers, data=json.dumps(payload), verify=False)
        if response.status_code == 200:
            print(response.status_code)
            print(response.url)
            print(response.text)
            json_data = json.loads(response.text)
        else:
            print(response.status_code)
            print(response.url)
            print(response.text)

            if logger is not None:
                logger.error(str(response.text))

    except Exception as e:
        print('Exception line number: {}'.format(
            sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
