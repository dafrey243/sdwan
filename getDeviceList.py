from prettytable import PrettyTable
import requests
import sys
import json
import time
import tabulate
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
        #	os.system('clear')
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

        # GET devices

        api_url = "/system/device/vedges"
        url = base_url + api_url
        response = requests.get(url=url, headers=headers, verify=False)
        if response.status_code == 200:
            mydata = json.loads(response.text)
            print json.dumps(mydata, indent=4)
            mydict = json.loads(response.text)
            x = PrettyTable()
            x.field_names = ['deviceModel', 'uuid', 'sudiSerialNumber', 'operation',
                             'hostname', 'deviceIP', 'site', 'version', 'platform-family']
            for item in mydict["data"]:
                deviceModel = item.get("deviceModel")
                uuid = item.get("uuid")
                sudiSerial = item.get("serialNumber")
                opmode = item.get("configOperationMode")
                deviceIP = item.get("system-ip")
                siteID = item.get('site-id')
                hostname = item.get('host-name')
                version = item.get('version')
                platformFamily = item.get('platformFamily')
                x.add_row([deviceModel, uuid, sudiSerial, opmode,
                           hostname, deviceIP, siteID, version, platformFamily])

            print(x)

        api_url = "/system/device/controllers"
        url = base_url + api_url
        response = requests.get(url=url, headers=headers, verify=False)

        if response.status_code == 200:
            mydata = json.loads(response.text)
            #print(json.dumps(mydata, indent=4))
            mydict = json.loads(response.text)

            x = PrettyTable()
            x.field_names = ['deviceModel', 'uuid', 'operation', 'hostname',
                             'deviceIP', 'site', 'version', 'Certificate expire', 'platform-family']
            try:
                for item in mydict["data"]:
                    deviceModel = item["deviceModel"]
                    uuid = item["uuid"]
                    opmode = item["configOperationMode"]
                    deviceIP = item["system-ip"]
                    siteID = item['site-id']
                    hostname = item['host-name']
                    version = item['version']
                    certexpire = item['expirationDate']
                    platformFamily = item['platformFamily']
                    x.add_row([deviceModel, uuid, opmode, hostname,
                               deviceIP, siteID, version, certexpire, platformFamily])
            except:
                print
            print(x)

        else:
            if logger is not None:
                logger.error(str(response.text))

    except Exception as e:
        print('Exception line number: {}'.format(
            sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
