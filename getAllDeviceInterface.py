import re
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

        # GET
        api_url = "/system/device/vedges"
        url = base_url + api_url
        response = requests.get(url=url, headers=headers, verify=False)

        if response.status_code == 200:
            mydata = json.loads(response.text)
        #   print json.dumps(mydata, indent=4)
            mydict = json.loads(response.text)

            for item in mydict["data"]:
                deviceModel = item.get("deviceModel")
                uuid = item.get("uuid")
                opmode = item.get("configOperationMode")
                DEVICE_ID = item.get("system-ip")
                siteID = item.get('site-id')
                hostname = item.get('host-name')
                version = item.get('version')

                if DEVICE_ID is not None:


                    api_url = "/device/interface?deviceId=" + DEVICE_ID + "&&&"
                    url = base_url + api_url
                    response = requests.get(url=url, headers=headers, verify=False)

                    if response.status_code == 200:
                        mydata = json.loads(response.text)
                        #print json.dumps(mydata, indent=4)
                        mydict = json.loads(response.text)
                        table = list()
	                ipaddresses = list()
                        headerrow = ['vdevice-name', 'vpn-id', 'vdevice-host-name', 'ifname', 'ip-address', 'ipv4-subnet-mask']
                        for item in mydict["data"]:
                            row = list()
                            for item1 in headerrow:
                                var = item.get(item1)
		                wanintf = item.get('ifname')
		                af = item.get('af-type')
		                wanip = item.get('ip-address')
                                if var is None:
                                    var = 'None'
                                row.append(var)
                            table.append(row)
                            if wanintf.find('GigabitEthernet1') != -1:
                                print wanip 
				ipaddresses.append(wanip)
                            elif wanintf.find('ge0/0') != -1 and af.find('ipv4') != -1:
                                ipadd = re.findall('[0-9]+(?:\.[0-9]+){3}', wanip )
                                print ipadd 
				ipaddresses.append(ipadd)

                        try:
                            print(tabulate.tabulate(table, headerrow, tablefmt="pretty"))
                        except UnicodeEncodeError:
                            print(tabulate.tabulate(table, headerrow, tablefmt="grid"))

        else:
            if logger is not None:
                logger.error(str(response.text))

    except Exception as e:
        print('Exception line number: {}'.format(
            sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
