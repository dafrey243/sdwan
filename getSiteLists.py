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
from authentication import Authentication
from mylogger import get_logger
from logging.handlers import TimedRotatingFileHandler
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings()

if __name__ == '__main__':

    try:
        os.system('clear')
        print("\n\n")
        mainfile = os.path.basename(__file__)
        log_level = logging.DEBUG
        logger = get_logger("log/cflowd.txt", log_level)

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

        # GET policyId

        api_url = "/template/policy/list/site"
        url = base_url + api_url
        response = requests.get(url=url, headers=headers, verify=False)

        if response.status_code == 200:
            mydata = json.loads(response.text)
        #    print(json.dumps(mydata, indent=4))

            mydict = json.loads(response.text)
        #    print(type(mydict))
#	    for key, value in mydict.items() :
#	        print( key, value)
            x = PrettyTable()
            y = PrettyTable()
            for item in mydict["data"]:
                x.field_names = ['listId', 'name', 'type', 'siteId']
                listId = item["listId"]
                name = item["name"]
                ptype = item["type"]
                siteId = item["entries"][0]['siteId']
                x.add_row([listId, name, ptype, siteId])
            print(x)
# 		x.clear_rows()

        else:
            if logger is not None:
                logger.error(str(response.text))

    except Exception as e:
        print('Exception line number: {}'.format(
            sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
