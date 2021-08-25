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
            definitionId = sys.argv[1]
        else:
            print "One arguments required. 1)App route definitionId.  Get the approute definition id from getPolicyAttributes.py scipt.\n"
            exit()

        # GET app route definition

        api_url = "/template/policy/definition/approute/" + definitionId
        url = base_url + api_url
        response = requests.get(url=url, headers=headers, verify=False)
        if response.status_code == 200:
            mydata = json.loads(response.text)
            #print json.dumps(mydata, indent=4)

            mydict = json.loads(response.text)
            x = PrettyTable()
            x.field_names = ['seq', 'field', 'Pref Color', 'type', 'backupColor',
                             'match', 'dscp', 'tosdec', 'toshex', 'sla', 'latency', 'loss', 'jitter']
            sequencelist = mydict.get('sequences', 'sequenceId')
            for item in sequencelist:
                sequenceId = item.get('sequenceId')
    	        if (sequenceId <= 131):
                    actions = item['actions']
                    ref = item['actions'][0]['parameter'][0]['ref']
                    field = item['actions'][0]['parameter'][1]['field']
                    value = item['actions'][0]['parameter'][1]['value']
                    pmeter = item['actions'][0]['parameter']
                    matchdict = item['match']
                    dscpfield = matchdict['entries'][0]['field']
                    dscpvalue = int(matchdict['entries'][0]['value'])
                    tosdec = dscpvalue << 2
                    toshex = "{:#04x}".format(tosdec)
                    # GET SLA Class
                    api_url = "/template/policy/list/sla/" + ref
                    url = base_url + api_url
                    response = requests.get(url=url, headers=headers, verify=False)
                    if response.status_code == 200:
                        myslaclass = json.loads(response.text)
                        #print json.dumps(myslaclass, indent=4)
			entries = myslaclass.get('entries')
                        name = myslaclass.get('name')
                        for i in entries:
                            jitter = i['jitter']
                            latency = i['latency']
                            loss = i['loss']
    
                    if len(pmeter) == 3:
                        backupColor = pmeter[2]['field']
                        ptype = "None"
                        x.add_row([sequenceId, field, value, ptype, backupColor, dscpfield,
                                   dscpvalue, tosdec, toshex, name, latency, loss, jitter])
                    if len(actions) == 2:
                        parameter = item['actions'][1]
                        ptype = item['actions'][1]['type']
                        backupColor = item['actions'][1]['parameter']
                        x.add_row([sequenceId, field, value, ptype, backupColor, dscpfield,
                                   dscpvalue, tosdec, toshex, name, latency, loss, jitter])
    
            print x

        else:
            if logger is not None:
                logger.error(str(response.text))

    except Exception as e:
        print('Exception line number: {}'.format(
            sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
