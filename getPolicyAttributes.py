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
#        os.system('clear')
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

        # GET policyId

        api_url = "/template/policy/vsmart"
        url = base_url + api_url
        response = requests.get(url=url, headers=headers, verify=False)

        if response.status_code == 200:
            mydata = json.loads(response.text)
        #    print json.dumps(mydata, indent=4)

            mydict = json.loads(response.text)
        #    print type(mydict)
#	    for key, value in mydict.iteritems() :
#	        print  key, value
            x = PrettyTable()
            y = PrettyTable()
            for item in mydict["data"]:
                x.field_names = ['policyName', 'Activated',
                                 'policyId', 'type', 'definitionId', 'siteLists']
                y.field_names = ['policyName', 'Active', 'policyId',
                                 'type', 'definitionId', 'siteLists', 'vpnLists']
                policyId = item["policyId"]
                policyName = item["policyName"]
                isPolicyActivated = item["isPolicyActivated"]
                policyDefinition = item["policyDefinition"]
                policyDefinitionDict = json.loads(policyDefinition)
                definitionId = policyDefinitionDict['assembly'][0]['definitionId']
                ptype = policyDefinitionDict['assembly'][0]['type']
                assembly = policyDefinitionDict['assembly']
                # i is a dict below and contains all the info.
                for i in assembly:
                    idefinitionId = i['definitionId']
                    itype = i['type']
                    entries = i.get("entries")
                    for i in entries:
                        siteLists = i.get("siteLists")
                        siteLists = listToString(siteLists)
                        ivpnLists = i.get("vpnLists")
                        if ivpnLists is not None:
                            ivpnLists = listToString(ivpnLists)
                        y.add_row([policyName, isPolicyActivated, policyId,
                                   itype, idefinitionId, siteLists, ivpnLists])

                x.add_row([policyName, isPolicyActivated, policyId,
                           ptype, definitionId, siteLists])
#	    print x
            print y
            templateId = raw_input('Enter definitionID for APP-ROUTE policy to retreive objects: ')
            os.system('python get_approute_definition.py %s' % (templateId))

        else:
            if logger is not None:
                logger.error(str(response.text))

    except Exception as e:
        print('Exception line number: {}'.format(
            sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
