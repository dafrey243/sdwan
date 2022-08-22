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

# Get below is for previous 2 hours
        # GET
        apilist = ["/statistics/interface?query=%7B%20%20%20%22query%22%3A%20%7B%20%20%20%20%20%22condition%22%3A%20%22AND%22%2C%20%20%20%20%20%22rules%22%3A%20%5B%20%20%20%20%20%20%20%7B%20%20%20%20%20%20%20%20%20%22value%22%3A%20%5B%20%20%20%20%20%20%20%20%20%20%20%222%22%20%20%20%20%20%20%20%20%20%5D%2C%20%20%20%20%20%20%20%20%20%22field%22%3A%20%22entry_time%22%2C%20%20%20%20%20%20%20%20%20%22type%22%3A%20%22date%22%2C%20%20%20%20%20%20%20%20%20%22operator%22%3A%20%22last_n_hours%22%20%20%20%20%20%20%20%7D%20%20%20%20%20%5D%20%20%20%7D%20%7D"]
        for api_url in apilist:
            url = base_url + api_url
            response = requests.get(url=url, headers=headers, verify=False)

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
                        if re.search("^(?!vdevice-dataKey|tx_pps|rx_pps|host_name|rx_kbps|tx_kbps|total_mbps|statcycletime|down_capacity_percentage|tenant|id|vip_idx|entry_time|vip_time|vmanage_system_ip|up_capacity_percentage)", k):
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
