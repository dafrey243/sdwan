import random
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

#        if len(sys.argv) == 2:
#           severity = sys.argv[1]
#        else:
#            print("One arguments required. 1)severity Critical, Major, Minor\n")
#            exit()

        # GET 
        apilist = ["/msla/devices"]
        for api_url in apilist:
            url = base_url + api_url
            print(url)
            response = requests.get(
                url=url, headers=headers, verify=False)
            if response.status_code == 200:
                mydata = json.loads(response.text)
                #print(json.dumps(mydata, indent=4))
                mydict = json.loads(response.text)
                table = list()
                headerrow = list()
                pheaderrow = list()
                uuidList = list()
                # Creates the header row.  camelHump and/or dash will be multiline cell
                for item in mydict["data"][0:1]:
                    for k, v in item.items():
                        # Take out keys when header row is too long
                        # Iterate over headerrow, and use pheaderrow for printing
                        if re.search("^(?!vdevice-dataKey|tag|subscription_id|licenses|UUID)", k):
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
                        uuid = item.get('UUID')
                        hostName = item.get('hostName')
                        if item1 == "hostName" and hostName != "-":
                            uuidList.append(uuid)
                        row.append(var)
                    table.append(row)

                try:
                    print(tabulate.tabulate(table, pheaderrow, tablefmt="pretty"))
                except UnicodeEncodeError:
                    print(tabulate.tabulate(table, headerrow, tablefmt="grid"))

            else:
                if logger is not None:
                    logger.error(str(response.text))

        # GET 
        x = PrettyTable()
        x.field_names = ['templateName', 'vaName', 'vaAccount', 'msla', 'licenses', 'saName', 'saAccount', 'licenseType']

        apilist = ["/msla/template"]
        templateList = list()
        for api_url in apilist:
            url = base_url + api_url
            print(url)
            response = requests.get(
                url=url, headers=headers, verify=False)
            if response.status_code == 200:
                mydata = json.loads(response.text)
                #print(json.dumps(mydata, indent=4))
                for item in mydata["result"]:
                    templateName = item.get("templateName")
                    vaName  = item.get("vaName")
                    msla = item.get("msla")
                    licenses = item.get("licenses")
                    line = licenses.split("\"")
                    licenses = line[7]
                    templateList.append(licenses)
                    saName = item.get("saName")
                    vaAccount = item["vaAccount"]
                    licenseType = item.get("licenseType")
                    saAccount = item.get("saAccount")
                    x.add_row([templateName, vaName, vaAccount,  msla, licenses, saName, saAccount, licenseType])
                                                    
                print(x)

            else:
                if logger is not None:
                    logger.error(str(response.text))
         
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
                print(response.text)
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
                       y.add_row([domain, account_id, name, vaaccountid, vaname, issavaused, savatemplateattached]) 
                       if domain == "sales-enablement.cisco.com" and vaname == "SP.Delivery.Arch.SP.SPNetworking":
                           myaccountid = account_id 
                           myvaaccountid = vaaccountid
                           mydomain = domain
                           mysa = name
                           myvsa = vaname
                print(y)
                print("syncing domain %s smart account %s (%s) virtual account %s (%s)" % (mydomain, mysa, myaccountid, myvsa, myvaaccountid))
                print(response.status_code)
            else:
                if logger is not None:
                    logger.error(str(response.text))

        apilist = ["/msla/va/License"]
        for api_url in apilist:
            url = base_url + api_url
            print(url)
            payload = [{"virtual_account_id":myvaaccountid,"licenseType":"prepaid"}]
            response = requests.post(
                url=url, headers=headers, data=json.dumps(payload), verify=False)
            if response.status_code == 200:
                mydata = json.loads(response.text)
                for k,v in mydata[0][myvaaccountid].items():
                    if v == "Routing DNA Advantage: Tier 0":
                        tag0 = k
                        display0 = v
                        dna0 = v.replace(" ", "")
                        print(tag0, dna0)
                    if v == "Routing DNA Advantage: Tier 1":
                        tag1 = k
                        display1 = v
                        dna1 = v.replace(" ", "")
                        print(tag1, dna1)
                    if v == "Routing DNA Advantage: Tier 2":
                        tag2 = k
                        display2 = v
                        dna2 = v.replace(" ", "")
                        print(tag2, dna2)
                    if v == "Routing DNA Advantage: Tier 3":
                        tag3 = k
                        display3 = v
                        dna3 = v.replace(" ", "")
                        print(tag3, dna3)

            #    print(json.dumps(mydata, indent=4))
            #    print(response.text)
                print(response.status_code)
            else:
                #print(json.dumps(mydata, indent=4))
                print(response.text)
                print(response.status_code)
                print(response.content)

# Attach Licenses to UUIDs
        x = PrettyTable()
        x.field_names = ['uuid', 'templateName', 'vaName', 'msla', 'licenses', 'saName', 'useExistingTemplate']

        exists = False
        apilist = ["/msla/template/licenses"]
        for api_url in apilist:
            url = base_url + api_url
            print(url)
            for uuid in uuidList:
                if uuid.startswith("C8K-32D") or uuid.startswith("C8K-9B46A13F-BDDA-B138-7EF2-41BBEBF5BB9B"):
                    tag = tag3
                    display = display3
                    dna = dna3
                elif uuid.startswith("C8K-AE7ED0F1") or uuid.startswith("C8K-229A486D-E10D-BE65-958D-D4A83ECB00D6"):
                    tag = tag2
                    display = display2
                    dna = dna2
                elif uuid.startswith("C8K") or uuid.startswith("ISR"):
                    tag = tag1
                    display = display1
                    dna = dna1
                else:
                    tag = tag0
                    display = display0
                    dna = dna0


# Does Template exist or not?
                print("length = %s" % (templateList))
                print(len(templateList))
                if (display in templateList):
                    exists = True
                else:
                    exists = False
                    # Update template list in realtime.
                    templateList.append(display)


                print("uuid  %s attached to license %s " % (uuid, display))
                payload = {"licenseTemplate":{"uuid":[uuid],"licenseType":"prepaid","useExistingTemplate":exists,"templateName":dna,"vaAccount":myvaaccountid,"vaName":myvsa,
                "saAccount":myaccountid,"saName":mysa,"msla":False,"licenses":[{"tag":tag,"display_name":display}] ,"subscriptionsUsed":[]}}
                # print(payload)
                response = requests.post(
                url=url, headers=headers, data=json.dumps(payload), verify=False)
                if response.status_code == 200:
                    mydata = json.loads(response.text)
                    print(json.dumps(mydata, indent=4))
               #    print(response.text)
                    print(response.status_code)
                    x.add_row([uuid, dna, myvsa, "false", display, mysa, exists])
                                                    

                else:
                    #print(json.dumps(mydata, indent=4))
                    print(response.text)
                    print(response.status_code)
                    print(response.content)

        print(x)

    except Exception as e:
        print('Exception line number: {}'.format(
            sys.exc_info()[-1].tb_lineno), type(e).__name__, e)


