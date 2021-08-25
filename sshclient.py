import paramiko
import time
import getpass
import os
#from host_file import network_devices
#from config_file import host_conf
from datetime import date

today = date.today()
tod = today.strftime("%B_%d_%Y")
#os.system('python getAllDeviceInterface.py')
#UN = raw_input("Username : ")
#PW = getpass.getpass("Password : ")
#UN = 'admin'
#PW = 'admin'

#vEdge
ipaddresses = ['192.168.0.20']
#ipaddresses = ['192.168.0.74', '10.64.1.201', '10.64.1.203', '192.168.0.20', '192.168.0.1', '192.168.0.2', '10.64.1.200']
config = open('config_file.txt')
lines = config.readlines()
# For loop allows you to specify number of hosts
for ip in ipaddresses:
    if ip in ['10.64.1.201', '192.168.0.74', '10.64.1.200', '10.64.1.203']:
	UN = 'admin'
	PW = 'admin'
    else:
        UN = 'dafrey'
        PW = 'grf1940'


    print ip
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, port=22, username=UN, password=PW)
    remote = ssh.invoke_shell()
    remote.send('term len 0\n')
    time.sleep(1)
    #This for loop allows you to specify number of commands  you want to enter
    #Dependent on the output of the commands you may want to tweak sleep time.
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

#cEdge

