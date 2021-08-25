from listToString import listToString
from prettytable import PrettyTable
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

        if len(sys.argv) >= 3:
            deviceIp = sys.argv[1]
            dscp = sys.argv[2:]
        else:
            with open('service_path.yaml', 'r') as file:
                data = file.read()

            print "Two or more arguments required. 1)system-ip of the device and dscp values. 11.1.1.87 46 32 24 16 8 4 0 \n"
            print "Other variables are in located in service_path.yaml file: \n" + data
            exit()

        # POST
        x = PrettyTable()
        for dscp in dscp:
            if logger is not None:
                logger.info("Loading service_path details from YAML\n")
            with open("service_path.yaml") as f:
                config = yaml.safe_load(f.read())
            remoteSystemIp = config["remoteSystemIp"]
            vpn = config["vpn"]
            interface = config["interface"]
            sourceIp = config["sourceIp"]
            destIp = config["destIp"]
            protocol = config["protocol"]

            api_url = "/device/tools/servicepath/" + deviceIp
            url = base_url + api_url
            payload = {
                "remoteSystemIp": remoteSystemIp,
                "vpn": vpn,
                "interface": interface,
                "sourceIp": sourceIp,
                "destIp": destIp,
                "protocol": protocol,
                "all": "true",
                "dscp": dscp
            }

            response = requests.post(
                url=url, headers=headers, data=json.dumps(payload), verify=False)

            if response.status_code == 200:
                mydata = json.loads(response.text)
                #print json.dumps(mydata, indent=4)
		#x = PrettyTable()
                mydict = json.loads(response.text)
                x.field_names = ['device', 'localColor', 'type', 'destIp', 'remoteSystemIp', 'sourcePort', 'sourceIp', 'destPort', 'remoteColor', 'dscp']
                for item in mydata['nexthops']:
                    localColor = item.get("localColor")
                    ptype = item["type"]
                    destIp = item.get("destIp")
                    remoteSystemIp = item.get("remoteSystemIp")
                    sourcePort = item.get("sourcePort")
                    sourceIp = item.get("sourceIp")
                    destPort = item.get("destPort")
                    remoteColor = item.get("remoteColor")
                    x.add_row([deviceIp, localColor, ptype, destIp, remoteSystemIp, sourcePort, sourceIp, destPort, remoteColor, dscp])

               # print x

            else:
                if logger is not None:
                    logger.error(str(response.text))
        print x

    except Exception as e:
        print('Exception line number: {}'.format(
            sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
