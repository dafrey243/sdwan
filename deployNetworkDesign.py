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

        if len(sys.argv) == 4:
            encs = sys.argv[1]
            deviceIds = sys.argv[2]
            profile = sys.argv[3]
        else:
            print("""**** Two arguments required. 1) Site ID number required e.g 151, 152, 153. 2) uuid from device list
            example command to execute: 
python deployNetworkDesign.py 151 ENCS5406/K9-FGL204910R7 ENCS1
python deployNetworkDesign.py 152 ENCS5408/K9-FGL201311DN ENCS2
python deployNetworkDesign.py 153 ENCS5406/K9-FGL2052104M ENCS3
or
python deployNetworkDesign.py 151 ENCS5406/K9-FGL204910R7 cleanup
python deployNetworkDesign.py 152 ENCS5408/K9-FGL201311DN cleanup
python deployNetworkDesign.py 153 ENCS5406/K9-FGL2052104M cleanup\n\n""")


            #os.system('python getDeviceList.py | grep "sudiSerialNumber\|ENCS\|\+"i')
            exit()
            
        apilist = ["/networkdesign"]
        for api_url in apilist:
            url = base_url + api_url
            response = requests.get(url=url, headers=headers, verify=False)

            if response.status_code == 200:
                x = PrettyTable()
                y = PrettyTable()
                mydata = json.loads(response.text)
                #print(json.dumps(mydata, indent=4))
                mydict = json.loads(response.text)
                table = list()
                headerrow = list()
                pheaderrow = list()

                sName = list()
                for item in mydict["data"][0]["definition"]["branches"]:
                    name = item["name"]
                    sName.append(name)
                    x.add_row([name])
                print(x)
                serviceName = raw_input('Enter a name from the table above: ')



                index = int(0)
                print(profile)
                print(serviceName)
                for name in sName:
                    for item in mydict["data"][0]["definition"]["branches"][index]["deviceProfiles"]:
                        y.field_names = ['name','deviceProfileName','deviceModel','deviceProfileId','deviceTemplateID']
                        deviceProfileName = item["deviceProfileName"]
                        deviceModel = item["deviceModel"]
                        deviceProfileId = item["deviceProfileId"]
                        deviceTemplateID = item["deviceTemplateID"]
                        if name == serviceName and profile == deviceProfileName:
                            mydeviceProfileId = deviceProfileId
                            mydeviceTemplateID = deviceTemplateID
                            print(mydeviceProfileId)
                            print(mydeviceTemplateID)
                        y.add_row([name, deviceProfileName, deviceModel, deviceProfileId, deviceTemplateID])
                    index += 1
                print(y)
###########


            else:
                if logger is not None:
                    logger.error(str(response.text))

# GET UUID
        MODEL = "vedge-C8000V"
        UUID = ""
        api_url = "/system/device/vedges?model=" + MODEL + "&state=tokengenerated&&&validity=valid"
        url = base_url + api_url
        response = requests.get(url=url, headers=headers, verify=False)
        if response.status_code == 200:
            mydata = json.loads(response.text)
            #print(json.dumps(mydata, indent = 4))
            for item in mydata['data']:
                UUID = item['uuid']
                break
        else:
            print(response.status_code)

        if UUID == "":
            api_url = "/system/device/vedges?model=" + MODEL + "&state=bootstrapconfiggenerated&&&validity=valid"
            url = base_url + api_url
            response = requests.get(url=url, headers=headers, verify=False)
            if response.status_code == 200:
                mydata = json.loads(response.text)
            #    print(json.dumps(mydata, indent = 4))
                for item in mydata['data']:
                    UUID = item['uuid']
                    break
            else:
                print(response.status_code)

# GET OTP
        api_url = "/system/device/bootstrap/device/" + UUID + "?configtype=cloudinit"
        url = base_url + api_url
        response = requests.get(url=url, headers=headers, verify=False)
        if response.status_code == 200:
            otp = re.search("otp : ([a-z0-9]+)", response.text).group(1)
           # print(UUID, otp)
        else:
            print(response.status_code)
# Lock Template
        api_url = "/networkdesign/profile/lock/" + mydeviceProfileId
        url = base_url + api_url
        response = requests.post(url=url, headers=headers, verify=False)
        if response.status_code == 200:
            mydata = json.loads(response.text)
            print("Locking deviceProfileId " + mydeviceProfileId)
            print json.dumps(mydata, indent=4)
        else:
            print(response.status_code)

#        os.system('python getDeviceList.py | grep "sudiSerialNumber\|ENCS\|\+"i')
#        deviceIds = raw_input('Enter uuid of device to provision: ')
#        deviceIds = "ENCS5408/K9-FGL201311DN"

        api_url = "/networkdesign/profile/template"
        url = base_url + api_url
        print(url)
        response = requests.get(url=url, headers=headers, verify=False)
        print(response.status_code)

        if response.status_code == 200:
            mydata = json.loads(response.text)
            #print(json.dumps(mydata, indent=4))
            mydict = json.loads(response.text)
            for item in mydict["data"]:
                templateName = item['templateName']
                templateId = item['templateId']
                if templateName == "ND_cleanup_cleanup_Template":
                    mytemplateId = templateId
                    break
        else:
            if logger is not None:
                logger.error(str(response.text))


# Input
        api_url = "/template/device/config/input"
        url = base_url + api_url
        print(url)
        payload = {"templateId":mytemplateId,"deviceIds":[deviceIds],"isEdited":False,"isMasterEdited":False}
        response = requests.post(url=url, data=json.dumps(payload), headers=headers, verify=False)
        if response.status_code == 200:
            #mydata = json.loads(response.text)
            #print json.dumps(mydata, indent=4)
            print(response.status_code)
        else:
            print(response.status_code)
# Attach Template
        api_url = "/networkdesign/profile/attachment/" +mydeviceProfileId
        url = base_url + api_url
        print(url)
        device = re.search(("ENCS540[0-9]+"), deviceIds).group(0)
        print(device + "-" + encs)
        if serviceName == "cleanup":
            
            payload = {"deviceTemplateList":[{"templateId":mytemplateId,"device":[{"csv-status":"complete","csv-deviceId":deviceIds,"csv-deviceIP":"11.11.1." + encs,"csv-host-name":"ENCS5406-" + encs,"//system/system-ip":"11.11.1." + encs,"//system/host-name":"ENCS5406-" + encs,"//system/site-id":encs,"/512/mgmt/interface/ip/address":"1.1.1.1/24","csv-templateId":mydeviceTemplateID}],"isEdited":False,"isMasterEdited":False}]}

        else:                

            payload = {"deviceTemplateList":[{"templateId":mydeviceTemplateID,"device":[{"csv-status":"complete","csv-deviceId":deviceIds,"csv-deviceIP":"11.11.1." + encs,"csv-host-name":device + "-" + encs,"//system/site-id":encs,"//system/host-name":device + "-" + encs,"//system/system-ip":"11.11.1." + encs,"/512/mgmt/interface/ip/address":"1.1.1.1/24","//vm_lifecycle/deployments/deployment/deployment-ROUTER_1/variable/UUID/val":UUID,"//vm_lifecycle/deployments/deployment/deployment-ROUTER_1/variable/OTP/val":otp,"//vm_lifecycle/deployments/deployment/deployment-ROUTER_1/variable/HOSTNAME/val":"csr" + encs,"//vm_lifecycle/deployments/deployment/deployment-ROUTER_1/variable/MPLS_IP/val":"172.27.2." + encs,"//vm_lifecycle/deployments/deployment/deployment-ROUTER_1/variable/LAN_IP/val":"10.0." + encs + ".1","SITEID":encs,"//vm_lifecycle/deployments/deployment/deployment-ROUTER_1/variable/SITEID/val":encs,"csv-templateId":mydeviceTemplateID}],"isEdited":False,"isMasterEdited":False}]}
        response = requests.post(url=url, data=json.dumps(payload), headers=headers, verify=False)
        print(json.dumps(payload, indent=4))
        if response.status_code == 200:
            #mydata = json.loads(response.text)
            #print json.dumps(mydata, indent=4)
            print(response.status_code)
        else:
            print(response.status_code)


    except Exception as e:
        print('Exception line number: {}'.format(
            sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
