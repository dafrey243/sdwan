from prettytable import PrettyTable
from flask import Flask
#app = Flask(__name__)

#@app.route("/")
def dscp2tos():
    loop = 0
    x = PrettyTable()
    dscpDec = [0, 1, 2, 3, 4, 8, 10, 12, 14, 16, 18, 20, 22,
               24, 26, 28, 30, 32, 34, 36, 38, 40, 44, 46, 48, 56]
    dscpPerHop = ['cs1', 'af11', 'af12', 'af13', 'cs2', 'af21', 'af22', 'af23', 'cs3', 'af31',
                  'af32', 'af33', 'cs4', 'af41', 'af42', 'af43', 'cs5', 'voiceA', 'ef', 'cs6', 'cs7']
    x.field_names = ['tos decimal', 'tos hexidecimal', 'tos binary', 'IP prec',
                     'dscp binary', 'dscp hexidecimal', 'dscp decimal', 'dscp per hop']
    for dscp in dscpDec:
        dscpBin = "{:06b}".format(dscp)
        dscpHex = "{:#04x}".format(dscp)
        tosDec = dscp << 2
        tosHex = "{:#04x}".format(tosDec)
        tosBin = "{:08b}".format(tosDec)
        tosPrecDec = tosDec >> 5
        loop += 1
        if loop <= 5:
            dscpPh = 'none'
        else:
            dscpPh = dscpPerHop[0]
            dscpPerHop.pop(0)
        x.add_row([tosDec, tosHex, tosBin, tosPrecDec,
                   dscpBin, dscpHex, dscp, dscpPh])

    print(x)

dscp2tos()
