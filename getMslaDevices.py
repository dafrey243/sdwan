import random
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
        sapassword = config["sapassword"]

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
        apilist = ["/msla/devices"]
        for api_url in apilist:
            url = base_url + api_url
            print(url)
            response = requests.get(
                url=url, headers=headers, verify=False)
            if response.status_code == 200:
                mydata = json.loads(response.text)
                #print(json.dumps(mydata, indent=4))
                mydict = json.loads(response.text)
                table = list()
                headerrow = list()
                pheaderrow = list()
                uuidList = list()
                # Creates the header row.  camelHump and/or dash will be multiline cell
                for item in mydict["data"][0:1]:
                    for k, v in item.items():
                        # Take out keys when header row is too long
                        # Iterate over headerrow, and use pheaderrow for printing
                        if re.search("^(?!vdevice-dataKey|vaAccount|subscription_id|tag|licenses|UUID)", k):
                            headerrow.append(k)
                            # Replace dash with newline to make multicell headerrow
                            k = k.replace("-", "\n")
                            # Add newline at each capital letter in camelHump syntax
                            k = re.sub("([A-Z])", '\n' r'\1', k)
                            pheaderrow.append(k)

                # Iterate of data to create row.  Boundry of a row defined by headerrow (keys)
                for item in mydict["data"]:
                    row = list()
                    for item1 in headerrow:
                        var = item.get(item1)
                        if item1 == 'lastupdated':
                            lastupdated = item.get('lastupdated')
                            lastupdated = lastupdated / 1000
                            var = datetime.datetime.fromtimestamp(lastupdated)
                        if item1 == 'idle-timeout-date':
                            lastupdated = item.get('idle-timeout-date')
                            lastupdated = lastupdated / 1000
                            var = datetime.datetime.fromtimestamp(lastupdated)
                        if var is None:
                            var = 'None'
                        uuid = item.get('UUID')
                        hostName = item.get('hostName')
                        if item1 == "hostName" and hostName != "-":
                            uuidList.append(uuid)
                        row.append(var)
                    table.append(row)

                try:
                    print(tabulate.tabulate(table, pheaderrow, tablefmt="pretty"))
                except UnicodeEncodeError:
                    print(tabulate.tabulate(table, headerrow, tablefmt="grid"))

            else:
                if logger is not None:
                    logger.error(str(response.text))

        # GET 
        x = PrettyTable()
        x.field_names = ['templateName', 'vaName', 'vaAccount', 'msla', 'licenses', 'saName', 'saAccount', 'licenseType']

        apilist = ["/msla/template"]
        for api_url in apilist:
            url = base_url + api_url
            print(url)
            response = requests.get(
                url=url, headers=headers, verify=False)
            if response.status_code == 200:
                mydata = json.loads(response.text)
                #print(json.dumps(mydata, indent=4))
                for item in mydata["result"]:
                    templateName = item.get("templateName")
                    vaName  = item.get("vaName")
                    msla = item.get("msla")
                    licenses = item.get("licenses")
                    line = licenses.split("\"")
                    licenses = line[7]
                    saName = item.get("saName")
                    vaAccount = item["vaAccount"]
                    licenseType = item.get("licenseType")
                    saAccount = item.get("saAccount")
                    x.add_row([templateName, vaName, vaAccount,  msla, licenses, saName, saAccount, licenseType])
                                                    
                print(x)


            else:
                if logger is not None:
                    logger.error(str(response.text))
         
    except Exception as e:
        print('Exception line number: {}'.format(
            sys.exc_info()[-1].tb_lineno), type(e).__name__, e)


