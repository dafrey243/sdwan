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
        # os.system('clear')
        print("\n\n")
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
#	os.system('python getDeviceList.py')
        if len(sys.argv) == 3:
            DEVICE_ID = sys.argv[1]
            vpn = sys.argv[2]
            vpn = "vpn-id=%s" % (vpn)
            api_url = "/device/ip/routetable?deviceId=" + DEVICE_ID + "&" + vpn + "&&&&"
        elif len(sys.argv) == 2:
            DEVICE_ID = sys.argv[1]
            api_url = "/device/ip/routetable?deviceId=" + DEVICE_ID + "&&&&"
        else:
            print("One argument required. 1)system-ip of the device to gather data\n Optional 2nd argument for VPN number")
            exit()

        url = base_url + api_url
        response = requests.get(url=url, headers=headers, verify=False)

        if response.status_code == 200:
            mydata = json.loads(response.text)
            print(json.dumps(mydata, indent=4))

            mydict = json.loads(response.text)
            x = PrettyTable()
            for item in mydict["data"]:
                x.field_names = ['vpn', 'protocol', 'prefix', 'nexthop-addr',
                                 'nexthop-ifname', 'tloc', 'color', 'encap', 'rstatus', 'vdevice-host-name']
                vpn = item["vpn-id"]
                protocol = item["protocol"]
                prefix = item["prefix"]
                nexthopaddr = item.get("nexthop-addr")
                nexthopifname = item.get("nexthop-ifname")
                rstatus = item.get("rstatus")
                vdevicehostname = item.get("vdevice-host-name")
                tloc = item.get("ip")
                color = item.get("color")
                encap = item.get("encap")
                x.add_row([vpn, protocol, prefix, nexthopaddr, nexthopifname,
                           tloc, color, encap, rstatus, vdevicehostname])
            print(x)
# 		x.clear_rows()

        else:
            if logger is not None:
                logger.error(str(response.text))

    except Exception as e:
        print('Exception line number: {}'.format(
            sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
