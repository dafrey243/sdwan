from listToString import listToString
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
        os.system('clear')
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
        directory = os.getcwd()
        if not os.path.exists('templates'):
            os.makedirs('templates')
        directory = os.path.join(directory, 'templates')

        api_url = "/template/device"
        url = base_url + api_url
        response = requests.get(url=url, headers=headers, verify=False)

        if response.status_code == 200:
            mydata = json.loads(response.text)
            mydict = json.loads(response.text)
            table = list()
            masterTemplate = list()
            headerrow = ['deviceType', 'configType', 'templateName',
                         'templateClass', 'devicesAttached', 'templateId', 'templateAttached']
            for item in mydict["data"]:
                configType = item.get('configType')
                row = list()
                for item1 in headerrow:
                    var = item.get(item1)
                    templateName = item.get('templateName')
                    templateId = item.get('templateId')
                    if var is None:
                        var = 'None'
                    row.append(var)
                table.append(row)

                if configType == 'template':
                    masterTemplate.append(item.get('templateId'))
                else:
                    continue
            try:
                print "Master Templates"
                print(tabulate.tabulate(table, headerrow, tablefmt="pretty"))
            except UnicodeEncodeError:
                print(tabulate.tabulate(table, headerrow, tablefmt="grid"))

        else:
            if logger is not None:
                logger.error(str(response.text))
        filename = ""
        # GET Master
        for ID in masterTemplate:
            x = PrettyTable()
            y = PrettyTable()
            table = list()
            x.field_names = ['templateName', 'templateId', 'templateType',
                             'templateClass', 'subtemplateId', 'subtemplateType']
            y.field_names = ['templateName', 'templateClass', 'Filename']
            generalTemplates = list()
            api_url = "/template/device/object/" + ID
            url = base_url + api_url
            response = requests.get(url=url, headers=headers, verify=False)

            if response.status_code == 200:
                mydata = json.loads(response.text)
                mydict = json.loads(response.text)
                templateName = mydict.get('templateName')
                deviceType = mydict.get('deviceType')
                configType = mydict.get('configType')
                templateClass = mydict.get('templateClass')

                writedir = os.path.join(directory, templateName)
                if not os.path.exists(writedir):
                    os.makedirs(writedir)
                filename = os.path.join(writedir, templateName)
                with open(filename, "w") as json_file:
                    json.dump(mydata, json_file, indent=4)
                    file.close(json_file)
                    y.add_row([templateName, templateClass, filename])

                for item in mydict['generalTemplates']:
                    templateId = item.get('templateId')
                    templateType = item.get('templateType')
                    for k, v in item.iteritems():
                        if k == 'subTemplates':
                            for item1 in v:
                                subtemplateType = item1.get('templateType')
                                subtemplateId = item1.get('templateId')
                            generalTemplates.append(subtemplateId)
                            x.add_row([templateName, templateId, templateType,
                                       templateClass, subtemplateId, subtemplateType])

                        else:
                            subtemplateId = 'None'
                            subtemplateType = 'None'
                    generalTemplates.append(templateId)
                    x.add_row([templateName, templateId, templateType,
                               templateClass, subtemplateId, subtemplateType])
                # Get General Templates
                    z = PrettyTable()
                    table = list()
                    z.field_names = ['templateName',
                                     'templateType', 'Filename']
                for ID in generalTemplates:

                    api_url = "/template/feature/object/" + ID
                    url = base_url + api_url
                    response = requests.get(
                        url=url, headers=headers, verify=False)

                    if response.status_code == 200:
                        mydata = json.loads(response.text)
                        mydict = json.loads(response.text)
                        gentemplateName = mydict.get('templateName')
                        gentemplateType = mydict.get('templateType')
                        writedir = os.path.join(directory, templateName)
                        filename = os.path.join(writedir, gentemplateName)
                        with open(filename, "w") as json_file:
                            json.dump(mydata, json_file, indent=4)
                            file.close(json_file)
                            z.add_row(
                                [gentemplateName, gentemplateType, filename])
                print "\n\nTemplates and Sub-Template data"
                print x
                print "Writing Master Templates"
                print y
                print "Writing General Templates"
                print z
                logger.debug('\n')
                logger.debug(x)
                logger.debug(y)
                logger.debug(z)


#                    else:
 #               	if logger is not None:
 #			    logger.error(str(response.text))

    except Exception as e:
        print('Exception line number: {}'.format(
            sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
