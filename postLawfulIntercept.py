from random import seed
from random import randint
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
        username = config["li_username"]
        password = config["li_password"]

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

#        if len(sys.argv) >= 3:
#           deviceIp = sys.argv[2:]
#        else:
#            print("Minimum two system ip addresses required\n")
#            exit()

        # POST
        for _ in range(1):
            myid = randint(1000000, 99999999)
            print(myid)
        apilist = ["/li/intercept"]
        for api_url in apilist:
            url = base_url + api_url
            payload = {"interceptId":"6061","description":"my intercept","edgeDevices":[{"systemIP":"11.1.1.60"},{"systemIP":"11.1.1.61"}],"apiUsers":[{"userName":"li-admin"}],"tenantId":"default"}

            response = requests.post(url=url, headers=headers, data=json.dumps(payload), verify=False)
            if response.status_code == 200:
                #mydata = json.loads(response.text)
                #print(json.dumps(mydata, indent=4))
                print(response.status_code)

            else:
                print(response.status_code)
                if logger is not None:
                    logger.error(str(response.text))
        #PUT activate
        apilist = ["/li/intercept/activate"]
        for api_url in apilist:
            url = base_url + api_url
            response = requests.put(url=url, headers=headers, verify=False)
            if response.status_code == 200:
                mydata = json.loads(response.text)
                print(json.dumps(mydata, indent=4))
                print(response.status_code)
            else:
                print(response.status_code)
                if logger is not None:
                    logger.error(str(response.text))

    except Exception as e:
        print('Exception line number: {}'.format(
            sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
