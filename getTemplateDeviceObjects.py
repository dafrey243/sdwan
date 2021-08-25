from listToString import listToString
from prettytable import PrettyTable
import requests
import sys
import tabulate
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
        #	os.system('clear')
        print "\n\n"
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

        if len(sys.argv) == 2:
            ID = sys.argv[1]
        else:
            print "One arguments required. 1)Template ID\n"
            exit()

        # GET

        api_url = "/template/device/object/" + ID
        url = base_url + api_url
        response = requests.get(url=url, headers=headers, verify=False)
        x = PrettyTable()

        if response.status_code == 200:
            mydata = json.loads(response.text)
       #     print json.dumps(mydata, indent=4)
            mydict = json.loads(response.text)
            table = list()
            x.field_names = ['templateName', 'templateId', 'templateType',
                             'templateClass', 'subtemplateId', 'subtemplateType']

            templateName = mydict.get('templateName')
            deviceType = mydict.get('deviceType')
            configType = mydict.get('configType')
            templateClass = mydict.get('templateClass')
            for item in mydict['generalTemplates']:
                templateId = item.get('templateId')
                templateType = item.get('templateType')
                subTemplates = item.get('subTemplates')
                if subTemplates is not None:
                    for item1 in subTemplates:
                        subtemplateId = item1.get('templateId')
                        subtemplateType = item1.get('templateType')
                else:
                    subtemplateId = 'None'
                    subtemplateType = 'None'
                x.add_row([templateName, templateId, templateType,
                           templateClass, subtemplateId, subtemplateType])

            print x
        else:
            if logger is not None:
                logger.error(str(response.text))

    except Exception as e:
        print('Exception line number: {}'.format(
            sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
