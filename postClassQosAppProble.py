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
        mydict = {'EF': '0', 'AF4': '1', 'BE': '2', 'AF1': '3', 'AF2': '4', 'AF3': '5'}
        for name, queue in mydict.items():      
            print(queue)
            base_url = "https://%s:%s/dataservice" % (vmanage_host, vmanage_port)
            api_url = "/template/policy/list/class"
            url = base_url + api_url
                      # {"name":"AF3","description":"Desc Not Required","type":"class","entries":[{"queue":"5"}]}
            payload = {"name":name,"description":"Desc Not Required","type":"class","entries":[{"queue":queue}]}
            response = requests.post(
                url=url, headers=headers, data=json.dumps(payload), verify=False)
            print(response.status_code)
            print(response.url)
            print(response.text)

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
