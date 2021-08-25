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
            DEVICE_ID = sys.argv[1]
            api_url = "/device/cflowd/flows?deviceId=" + DEVICE_ID + "&&&&"
        elif len(sys.argv) == 3:
            DEVICE_ID = sys.argv[1]
            destip = sys.argv[2]
            api_url = "/device/cflowd/flows?deviceId=" + \
                DEVICE_ID + "&&&" + "dest-ip=" + destip
        else:
            print("One arguments required. 1 system-ip of the device to gather data\n"
            "2 Second argument optional and is the dest ip address\n")
            exit()

        # GET
        x = PrettyTable()
        y = PrettyTable()
        url = base_url + api_url
        response = requests.get(url=url, headers=headers, verify=False)

        if response.status_code == 200:
            mydata = json.loads(response.text)
            print json.dumps(mydata, indent=4)
            mydict = json.loads(response.text)
            table = list()
            devicetable = list()
            pheaderrow = ['dest-ip', 'src-ip', 'egress\nintf', 'ingress\nintf-name', 'vdevice-name', 'src\nport', 'icmp\nopcode', 'vpn-id', 'vdevice\nhost-name',
                          'dest\nport', 'dscp', 'egress\nintf-name', 'total-bytes', 'ingress\nintf', 'ip\nproto']

            headerrow = ['dest-ip', 'src-ip', 'egress-intf', 'ingress-intf-name', 'vdevice-name', 'src-port', 'icmp-opcode', 'vpn-id', 'vdevice-host-name',
                         'dest-port', 'dscp', 'egress-intf-name', 'total-bytes', 'ingress-intf', 'ip-proto']
            for item in mydict["data"]:
                row = list()
                for item1 in headerrow:
                    var = item.get(item1)
                    if var is None:
                        var = 'None'
                    row.append(var)
                table.append(row)
            try:
		tabledata = sorted(table, key=lambda table: table[10], reverse=True)
                print(tabulate.tabulate(tabledata, pheaderrow, tablefmt="pretty"))
            except UnicodeEncodeError:
                print(tabulate.tabulate(table, headerrow, tablefmt="grid"))

        else:
            if logger is not None:
                logger.error(str(response.text))

    except Exception as e:
        print('Exception line number: {}'.format(
            sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
