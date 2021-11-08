from optparse import OptionParser
from CryptoMobile.Milenage import Milenage
from gSECURITY import *


class auth():

    def __init__(self, mcc, mnc, imsi, ki, op, opc):
        self.mcc = mcc
        self.mnc = mnc
        self.imsi = imsi 
        self.ki = ki
        self.op = op
        self.opc = opc

    def auth_5g_aka(self, rand, autn):
        AUTS = None
        RES, CK, IK = return_res_ck_ik(rand, autn, self.ki, self.op, self.opc)
        print('RES', RES)

        res_star = return_res_star(self.mcc+self.mnc, rand, RES, CK, IK)
        print('RES*', toHex(res_star))
        print('HRES*', toHex(return_hres_star(rand, res_star)))
        #self.kausf, self.kseaf, self.kamf, self.KEY_EA[1],self.KEY_EA[2],self.KEY_EA[3],self.KEY_IA[1],self.KEY_IA[2],self.KEY_IA[3] = return_all_possible_keys(self.mcc+self.mnc,AUTN,CK,IK,abba,self.imsi, True)


#abstraction functions
def milenage_res_ck_ik(ki, op, opc, rand):
    rand = unhexlify(rand)
    ki = unhexlify(ki)
    if op == None: 
        opc = unhexlify(opc)
        op = 16*b'\x00' #dummy since we will set opc directly
        m = Milenage(op)
        m.set_opc(opc)
    else:
        op = unhexlify(op)
        m = Milenage(op)
    res, ck, ik, ak = m.f2345(ki, rand)
    return toHex(res), toHex(ck), toHex(ik)


def return_res_ck_ik(rand, autn, ki, op, opc):
    try:
        return milenage_res_ck_ik(ki, op, opc, rand)
    except:
        print('Unable to calculate Milenage RES/CK/IK. Check KI, OP or OPC. Using DEFAULT RES, CK and IK')
        return


def toHex(value): # bytes hex string
    if value is not None:
        return hexlify(value).decode('utf-8')
    else:
        return None


def fromHex(value): # hex string to bytes
    return unhexlify(value)


def main():
    parser = OptionParser()
    parser.add_option("-I", "--imsi", dest="imsi", help="IMSI")
    parser.add_option("-M", "--mcc", dest="mcc", help="MCC of ePDG (3 digits)")
    parser.add_option("-N", "--mnc", dest="mnc", help="MNC of ePDG (3 digits)")
    parser.add_option("-K", "--ki", dest="ki", help="ki for Milenage (if not using option -m)")
    parser.add_option("-P", "--op", dest="op", help="op for Milenage (if not using option -m)")    
    parser.add_option("-C", "--opc", dest="opc", help="opc for Milenage (if not using option -m)") 
    parser.add_option("-R", "--rand", dest="rand", help="RAND")
    parser.add_option("-A", "--autn", dest="autn", help="AUTN")

    (options, args) = parser.parse_args()

    a = auth(options.mcc, options.mnc, options.imsi, options.ki,
        options.op, options.opc)
    print(f'K: {options.ki}')

    a.auth_5g_aka(options.rand, options.autn)


if __name__ == "__main__":
    main()

#  -M 208 -N 93 -I 2089300007487 -K 5122250214c33e723a5dd523fc145fc0 -P c9e8763286b5b9ffbdf56e1297d0887b
#####################################################################################################################################################################################    
# Example for free5GC:
#
# python3 nwu_emulator.py  -a internet -d 172.16.62.131 -M 208 -N 93 -I 208930000000003 -K 8baf473f2f8fd09487cccbd7097c6862 -P 8e27b6af0e692e750f32667a3b14605d
#
# python3 nwu_emulator.py  -a internet -d 172.16.62.131 -M 208 -N 93 -I 2089300007487 -K 5122250214c33e723a5dd523fc145fc0 -P c9e8763286b5b9ffbdf56e1297d0887b
#
#####################################################################################################################################################################################
