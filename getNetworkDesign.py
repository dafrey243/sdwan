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

        apilist = ["/networkdesign"]
        for api_url in apilist:
            url = base_url + api_url
            response = requests.get(url=url, headers=headers, verify=False)

            if response.status_code == 200:
                x = PrettyTable()
                y = PrettyTable()
                mydata = json.loads(response.text)
                #print(json.dumps(mydata, indent=4))
                mydict = json.loads(response.text)
                table = list()
                headerrow = list()
                pheaderrow = list()
                serviceName = list()
                for item in mydict["data"][0]["definition"]["branches"]:
                    name = item["name"]
                    serviceName.append(name)
                    x.add_row([name])
                #print(x)


                index = int(0)
                for name in serviceName:
                    for item in mydict["data"][0]["definition"]["branches"][index]["deviceProfiles"]:
                        y.field_names = ['name','deviceProfileName','deviceModel','deviceProfileId','deviceTemplateID']
                        deviceProfileName = item["deviceProfileName"]
                        deviceModel = item["deviceModel"]
                        deviceProfileId = item["deviceProfileId"]
                        deviceTemplateID = item["deviceTemplateID"]
                        y.add_row([name, deviceProfileName, deviceModel, deviceProfileId, deviceTemplateID])
                    index += 1
                print(y)

            else:
                if logger is not None:
                    logger.error(str(response.text))

    except Exception as e:
        print('Exception line number: {}'.format(
            sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
