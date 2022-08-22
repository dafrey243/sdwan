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

        if len(sys.argv) == 2:
            deviceIp = sys.argv[1]
        else:
            print("One arguments required. 1)system-ip of the device to gather data\n")
            exit()

        # GET
        apilist = ["/statistics/dpi/applications?query=%7B%22query%22%3A%7B%22condition%22%3A%22AND%22%2C%22rules%22%3A%5B%7B%22value%22%3A%5B%2224%22%5D%2C%22field%22%3A%22entry_time%22%2C%22type%22%3A%22date%22%2C%22operator%22%3A%22last_n_hours%22%7D%2C%7B%22value%22%3A%5B%22" + deviceIp +
                   "%22%5D%2C%22field%22%3A%22vdevice_name%22%2C%22type%22%3A%22string%22%2C%22operator%22%3A%22in%22%7D%5D%7D%2C%22a%20ggregation%22%3A%7B%22field%22%3A%5B%7B%22property%22%3A%22family%22%2C%22size%22%3A200%2C%22sequence%22%3A1%7D%5D%2C%22metrics%22%3A%5B%7B%22property%22%3A%22octets%22%2C%22type%22%3A%22sum%22%2C%22order%22%3A%22desc%22%7D%5D%7D%7D&"]
        for api_url in apilist:
            url = base_url + api_url

            response = requests.get(url=url, headers=headers, verify=False)
            if response.status_code == 200:
                mydata = json.loads(response.text)
                print(json.dumps(mydata, indent=4))
                mydict = json.loads(response.text)
                table = list()
                headerrow = list()
                pheaderrow = list()
                # Creates the header row.  camelHump and/or dash will be multiline cell
                for item in mydict["data"][0:1]:
                    for k, v in item.items():
                        # Take out keys when header row is too long
                        # Iterate over headerrow, and use pheaderrow for printing
                        if re.search("^(?!mydevice)", k):
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
