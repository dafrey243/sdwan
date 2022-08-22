import datetime
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

        now = datetime.datetime.now()
        date_time_stamp = now.strftime("%h_%d_%4Y")

        # GET
        x = PrettyTable()
        y = PrettyTable()
        api_url = "/device"
        url = base_url + api_url
        response = requests.get(url=url, headers=headers, verify=False)

        if response.status_code == 200:
            mydata = json.loads(response.text)
            #print(json.dumps(mydata, indent=4))
            mydict = json.loads(response.text)
            table = list()
            devicedict = {}
            devicetable = list()
            for item in mydict["data"]:
                personality = item['personality']
                deviceIP = item["system-ip"]
                reachability = item['reachability']
                uuid = item.get('uuid')
                hostname = item.get('host-name')
                deviceIP = item["system-ip"]
                if personality == "vedge":
                    devicedict.update({hostname: deviceIP})

        x = PrettyTable()
        currentTime = int(time.time())
        currentTime = currentTime * 1
        #currentTime = currentTime - 5000
        previousday = currentTime - 8640
        print(previousday,currentTime)
        for host, systemip in devicedict.items():
            print(systemip)
            payload = {"device_id":systemip,"data_type":"DPI","time_period":"CUSTOM","start_time":currentTime,"end_time":previousday}
	    #payload = {"device_id":systemip,"data_type":"DPI","time_period":"LAST_N_HOURS","value":"3"}
            api_url = '/statistics/on-demand/queue'
            url = base_url + api_url
            response = requests.post(url=url, data=json.dumps(payload), headers=headers, verify=False)
            if response.status_code == 200:
                mydata = json.loads(response.text)
                print(json.dumps(mydata, indent=4))
                mydict = json.loads(response.text)

            else:
                mydata = json.loads(response.text)
                print json.dumps(mydata, indent=4)
                print ""
                print "HTTP Code:     ", response.status_code
                print "ERROR MESSAGE: ", mydata['error']['message']
                print "ERROR DETAILS: ", mydata['error']['details']

    except Exception as e:
        print('Exception line number: {}'.format(
            sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
