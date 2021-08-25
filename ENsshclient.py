import paramiko
import time
import re
import os
#from host_file import network_devices
#from config_file import host_conf
from datetime import date
import requests
import sys
import ipaddress
import json
import time
import logging
import yaml
import disable_https_warning
from authentication import Authentication
from mylogger import get_logger
from logging.handlers import TimedRotatingFileHandler
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings()

today = date.today()
tod = today.strftime("%B_%d_%Y")
#os.system('python getAllDeviceInterface.py')
#UN = raw_input("Username : ")
#PW = getpass.getpass("Password : ")
#UN = 'admin'
#PW = 'admin'
# API to get system_ip addresses for the network

if __name__ == '__main__':

    try:
        # os.system('clear')
        #       print "\n\n"
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

        api_url = "/device"
        url = base_url + api_url
        response = requests.get(url=url, headers=headers, verify=False)
	deviceList = []

        if response.status_code == 200:
            mydict = json.loads(response.text)

            for item in mydict["data"]:
		var = item['deviceId']
		m = re.match(r"11.1[1]?.1.[0-6]",var)
		if m:    
		    deviceList.append(item['deviceId'])
	print deviceList
	ipadd = []	
	for DEVICE_ID in deviceList:
	    #print "deviceId = " + DEVICE_ID
            api_url = "/device/interface?deviceId=" + DEVICE_ID + '&vpn-id=512&&'
            url = base_url + api_url
            response = requests.get(url=url, headers=headers, verify=False)
	
            if response.status_code == 200:
                mydict = json.loads(response.text)
		#print json.dumps(mydict['data'], indent=4)
                for item in mydict["data"]:
	            var = item['ip-address']	
		    if var is not "-":
		        myip = ipaddress.ip_interface(item['ip-address'])
                        myip = myip.ip
                        myip = str(ipaddress.IPv4Address(myip)) 
		        ipadd.append(myip)

            #print ipadd
 
        config = open('config_file.txt')
        lines = config.readlines()
        for ip in ipadd:
            UN = 'admin'
            PW = 'admin'
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, port=22, username=UN, password=PW)
            remote = ssh.invoke_shell()
            remote.send('term len 0\n')
            time.sleep(1)
            for command in lines:
	        command = command.strip()
                remote.send('%s\n' % command)
                time.sleep(2)
                buf = remote.recv(965000)
                print buf
                f = open(ip + '_' + tod + '.txt', 'a')
                f.write(buf)
                f.close()
            ssh.close()

        else:
            if logger is not None:
                logger.error(str(response.text))

    except Exception as e:
        print('Exception line number: {}'.format(
            sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
             
