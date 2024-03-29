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
        # os.system('clear')
        #	print("\n\n")
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

        # GET
        vsmartup = 0
        vsmartdown = 0
        vbondup = 0
        vbonddown = 0
        vmanageup = 0
        vmanagedown = 0
        vedgeup = 0
        vedgedown = 0

        x = PrettyTable()
        y = PrettyTable()
        api_url = "/device"
        url = base_url + api_url
        response = requests.get(url=url, headers=headers, verify=False)

        if response.status_code == 200:
            mydata = json.loads(response.text)
        #    print(json.dumps(mydata, indent=4))
            mydict = json.loads(response.text)
            table = list()
            devicetable = list()
            pheaderrow = ['deviceId', 'host-name', 'site-id', 'state', 'state_description', 'control\nConnections', 'personality', 'device\nmodel',
                          'omp\nPeers', 'bfd\nSessions', 'reachability', 'platform', 'version']

            headerrow = ['deviceId', 'host-name', 'site-id', 'state', 'state_description', 'controlConnections', 'personality', 'device-model',
                         'ompPeers', 'bfdSessions', 'reachability', 'platform', 'version']
            x.field_names = ['vSmart Up',
                             'WANedge Up', 'vBond Up', 'vManage Up']
            y.field_names = ['vSmart Dn',
                             'WANedge Dn', 'vBond Dn', 'vManage Dn']
            for item in mydict["data"]:
                personality = item['personality']
                reachability = item['reachability']
                if reachability == 'reachable':
                    if personality == 'vsmart':
                        vsmartup += 1
                    elif personality == 'vbond':
                        vbondup += 1
                    elif personality == 'vmanage':
                        vmanageup += 1
                    else:
                        vedgeup += 1
                else:
                    if personality == 'vsmart':
                        vsmartdown += 1
                    elif personality == 'vbond':
                        vbonddown += 1
                    elif personality == 'vmanage':
                        vmanagedown += 1
                    else:
                        vedgedown += 1

                row = list()
                for item1 in headerrow:
                    var = item.get(item1)
                    if var is None:
                        var = 'None'
                    row.append(var)
                table.append(row)
            x.add_row([vsmartup, vedgeup, vbondup, vmanageup, ])
            y.add_row([vsmartdown, vedgedown, vbonddown, vmanagedown])
            try:
                print(x)
                print(y)
                print(tabulate.tabulate(table, pheaderrow, tablefmt="pretty"))

            except UnicodeEncodeError:
                print(tabulate.tabulate(table, headerrow, tablefmt="grid"))

        else:
            if logger is not None:
                logger.error(str(response.text))

    except Exception as e:
        print('Exception line number: {}'.format(
            sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
