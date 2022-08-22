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

#        if len(sys.argv) == 2:
#           severity = sys.argv[1]
#        else:
#            print("One arguments required. 1)severity Critical, Major, Minor\n")
#            exit()

        # POST
        currentTime = int(time.time())
        currentTime = currentTime  
        previousday = currentTime - 17000
        currentTime = datetime.datetime.fromtimestamp(currentTime).strftime("%Y-%m-%dT%H:%M:%S")
        previousday = datetime.datetime.fromtimestamp(previousday).strftime("%Y-%m-%dT%H:%M:%S")
        print(previousday,currentTime)
        api_url = "/alarms"
        previoushours = 2        
        payloadList = ["bgp_router_up", "bgp_router_down"]
 
        for payloadValue in payloadList:
            url = base_url + api_url
            payload = {
                "query": {
                    "condition": "AND",
                    "rules": [
                        {
                            "value": [
                                "2"
                            ],
                            "field": "entry_time",
                            "type": "date",
                            "operator": "last_n_hours"
                        },
                        {
                            "value": [
                                payloadValue
                            ],
                            "field": "rulename",
                            "type": "string",
                            "operator": "in"
                        }
                    ]
                }
            }

            response = requests.post(
                url=url, headers=headers, data=json.dumps(payload), verify=False)
            if response.status_code == 200:
                mydata = json.loads(response.text)
                print(json.dumps(mydata, indent=4))
                mydict = json.loads(response.text)
                table = list()
                headerrow = list()
                pheaderrow = list()
                # Creates the header row.  camelHump and/or dash will be multiline cell
                for item in mydict["data"][0]["consumed_events"][0:1]:
                    for k, v in item.items():
                        # Take out keys when header row is too long
                        # Iterate over headerrow, and use pheaderrow for printing
                        if re.search("^(?!mydevice|builtBy|component|linkupdate|vpn-id|receive_time|eventCreationTime|local-address)", k):
                            headerrow.append(k)
                            # Replace dash with newline to make multicell headerrow
                            k = k.replace("-", "\n")
                            # Add newline at each capital letter in camelHump syntax
                            k = re.sub("([A-Z])", '\n' r'\1', k)
                            pheaderrow.append(k)

                # Iterate of data to create row.  Boundry of a row defined by headerrow (keys)
                for item in mydict["data"][0]["consumed_events"]:
                    row = list()
                    for item1 in headerrow:
                        var = item.get(item1)
                        if item1 == 'entry_time':
                            lastupdated = item.get('entry_time')
                            lastupdated = lastupdated / 1000
                            var = datetime.datetime.fromtimestamp(lastupdated)
                        if item1 == 'statcycletime':
                            lastupdated = item.get('statcycletime')
                            lastupdated = lastupdated / 1000
                            var = datetime.datetime.fromtimestamp(lastupdated)

                        if item1 == 'event':
                            var = 'None'

                        if var is None:
                            var = 'None'

                        row.append(var)
                    table.append(row)

                #try:
                #    print(url)
                    #print("previous_hours %s") % previoushours
                    #print(payloadValue)
                    
                #    print(tabulate.tabulate(table, pheaderrow, tablefmt="pretty"))
                #except UnicodeEncodeError:
                 #   print(tabulate.tabulate(table, headerrow, tablefmt="grid"))

            try:
                print(url)
                #print("previous_hours %s") % previoushours
                #print(payloadValue)

                print(tabulate.tabulate(table, pheaderrow, tablefmt="pretty"))
            except UnicodeEncodeError:
                print(tabulate.tabulate(table, headerrow, tablefmt="grid"))


            else:
                if logger is not None:
                    logger.error(str(response.text))

    except Exception as e:
        print('Exception line number: {}'.format(
            sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
