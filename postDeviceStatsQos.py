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

        if len(sys.argv) == 3:
            deviceIp = sys.argv[1]
            interface = sys.argv[2]
        else:
            print(
                "Two arguments required. 1)system-ip of the device to gather data, 2nd local interface\n")
            exit()

        # POST
        apilist = ["/statistics/qos"]
        for api_url in apilist:
            url = base_url + api_url
            payload = {
                "query": {
                    "condition": "AND",
                    "rules": [
                        {
                            "value": [
                                "1"
                            ],
                            "field": "entry_time",
                            "type": "date",
                            "operator": "last_n_hours"
                        },
                        {
                            "value": [
                                interface
                            ],
                            "field": "interface",
                            "type": "string",
                            "operator": "in"
                        },
                        {
                            "value": [
                                deviceIp
                            ],
                            "field": "vdevice_name",
                            "type": "string",
                            "operator": "in"
                        },
                    ]
                },
                "aggregation": {
                    "field": [
                        {
                            "property": "name",
                            "sequence": 1
                        },
                        {
                            "property": "proto",
                            "sequence": 2
                        }
                    ],
                    "histogram": {
                        "property": "entry_time",
                        "type": "minute",
                        "interval": 30,
                        "order": "asc"
                    },
                    "metrics": [
                        {
                            "property": "latency",
                            "type": "avg"
                        },
                        {
                            "property": "loss",
                            "type": "avg"
                        },
                        {
                            "property": "loss_percentage",
                            "type": "avg"
                        },
                        {
                            "property": "vqoe_score",
                            "type": "avg"
                        }
                    ]
                }
            }

            response = requests.post(
                url=url, headers=headers, data=json.dumps(payload), verify=False)
            if response.status_code == 200:
                mydata = json.loads(response.text)
                #print(json.dumps(mydata, indent=4))
                mydict = json.loads(response.text)
                table = list()
                headerrow = list()
                pheaderrow = list()
                # Creates the header row.  camelHump and/or dash will be multiline cell
                for item in mydict["data"][0:1]:
                    for k, v in item.items():
                        # Take out keys when header row is too long
                        # Iterate over headerrow, and use pheaderrow for printing
                        if re.search("^(?!vip_time|drop_in_pps|tenant|statcycletime|vip_idx|id|vmanage_system_ip)", k):
                            headerrow.append(k)
                            # Replace dash with newline to make multicell headerrow
                            k = k.replace("_", "\n")
                            # Add newline at each capital letter in camelHump syntax
                            k = re.sub("([A-Z])", '\n' r'\1', k)
                            pheaderrow.append(k)

                # Iterate of data to create row.  Boundry of a row defined by headerrow (keys)
                for item in mydict["data"]:
                    row = list()
                    for item1 in headerrow:
                        var = item.get(item1)
                        if item1 == 'entry_time':
                            lastupdated = item.get('entry_time')
                            lastupdated = lastupdated / 1000
                            var = datetime.datetime.fromtimestamp(lastupdated)
                        if var is None:
                            var = 'None'
                        row.append(var)
                    table.append(row)

                try:
                    print(url)
                    print(tabulate.tabulate(table, pheaderrow, tablefmt="pretty"))
                except UnicodeEncodeError:
                    print(tabulate.tabulate(table, headerrow, tablefmt="grid"))

            else:
                if logger is not None:
                    logger.error(str(response.text))

    except Exception as e:
        print('Exception line number: {}'.format(
            sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
