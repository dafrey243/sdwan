from listToString import listToString
from prettytable import PrettyTable
import tabulate
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

        # GET
        x = PrettyTable()

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
                    api_url = "/device/bfd/sessions?deviceId=" + DEVICE_ID + "&&&&"
                    url = base_url + api_url
                    response = requests.get(
                        url=url, headers=headers, verify=False)

                    if response.status_code == 200:
                        mydata = json.loads(response.text)
                        #print json.dumps(mydata, indent=4)
                        headerrow = ['system-ip', 'site-id', 'state', 'local-color', 'color',
                                     'src-ip', 'dst-ip', 'src-port', 'dst-port', 'uptime', 'local-device']
                        table = list()
                        mydict = json.loads(response.text)
                        for item in mydict["data"]:
                            row = [item["system-ip"],
                                   item["site-id"],
                                   item["state"],
                                   item.get("local-color"),
                                   item.get("color"),
                                   item.get("src-ip"),
                                   item.get("dst-ip"),
                                   item.get("src-port"),
                                   item.get("dst-port"),
                                   item.get("uptime"),
                                   item.get("vdevice-name")]
                            table.append(row)
                    try:
                        print(tabulate.tabulate(
                            table, headerrow, tablefmt="pretty"))
                    except UnicodeEncodeError:
                        print(tabulate.tabulate(
                            table, headerrow, tablefmt="grid"))

                        #x.add_row([systemip, siteid, state, localcolor, color, srcip, dstip, srcport, dstport, uptime, vdevicename])
                    # x.sortby="site-id"
                    #print x
                    # x.clear_rows()

        else:
            if logger is not None:
                logger.error(str(response.text))

    except Exception as e:
        print('Exception line number: {}'.format(
            sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
