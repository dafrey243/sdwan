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
        sapassword = config["sapassword"]

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

        # POST
        apilist = ["/smartLicensing/authenticate"]
        for api_url in apilist:
            url = base_url + api_url
            print(url)
            payload = {"username":"dafrey@cisco.com","password":sapassword}
            response = requests.post(
                url=url, headers=headers, data=json.dumps(payload), verify=False)
            if response.status_code == 200:
                mydata = json.loads(response.text)
                print(json.dumps(mydata, indent=4))
               # print(response.text)
                print(response.status_code)

            else:
                if logger is not None:
                    logger.error(str(response.text))

        y = PrettyTable()
        y.field_names = ['domain', 'account_id', 'name', 'vaaccountid', 'vaname', 'issavaused', 'savatemplateattached']

        apilist = ["/smartLicensing/fetchAccounts?mode=online"]
        for api_url in apilist:
            url = base_url + api_url
            print(url)
            response = requests.get(
                url=url, headers=headers, verify=False)
            if response.status_code == 200:
                mydict = json.loads(response.text)
                for accounts in mydict["accounts"]:
                    domain = accounts.get("domain")
                    account_id = accounts.get("account_id")
                    name = accounts.get("name")
                    virtual_accounts = accounts.get("virtual_accounts")
                    for d in virtual_accounts:
                       vaaccountid = d["vaaccountid"]
                       vaname = d["name"]
                       issavaused = d['issavaused']
                       savatemplateattached = d['savatemplateattached']
                #       y.add_row([domain, account_id, name, vaaccountid, vaname, issavaused, savatemplateattached]) 
                       if domain == "sales-enablement.cisco.com" and vaname == "SP.Delivery.Arch.SP.SPNetworking":
                           myaccountid = account_id 
                           myvaaccountid = vaaccountid
                           mydomain = domain
                           mysa = name
                           myvsa = vaname
                           y.add_row([domain, account_id, name, vaaccountid, vaname, issavaused, savatemplateattached]) 
                print(y)
                print(response.status_code)
            else:
                if logger is not None:
                    logger.error(str(response.text))

    except Exception as e:
        print('Exception line number: {}'.format(
            sys.exc_info()[-1].tb_lineno), type(e).__name__, e)


