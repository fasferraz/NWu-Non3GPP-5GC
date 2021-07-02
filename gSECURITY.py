from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
from CryptoMobile.CM import *
from binascii import hexlify, unhexlify
import struct


DIRECTION_DOWN = 1
DIRECTION_UP =   0


BEARER_ID_NAS_CONNECTION_IDENTIFIER_3GPP = 0x1
BEARER_ID_NAS_CONNECTION_IDENTIFIER_NON_3GPP = 0x2

def bcd_bytes(chars):  
    bcd_string = ""
    for i in range(len(chars) // 2):
        bcd_string += chars[1+2*i] + chars[2*i]
    return bytes(bytearray.fromhex(bcd_string))

def return_plmn(mccmnc):
    mccmnc = str(mccmnc)
    if len(mccmnc)==5:
        return bcd_bytes(mccmnc[0] + mccmnc[1] + mccmnc[2] + 'f' + mccmnc[3] + mccmnc[4]) 
    elif len(mccmnc)==6:
        return bcd_bytes(mccmnc[0] + mccmnc[1] + mccmnc[2] + mccmnc[5] + mccmnc[3] + mccmnc[4]) 
    else:
        return b''

def return_5g_plmn(mccmnc):
    mcc = mccmnc[0:3]
    if len(mccmnc)==5:
        mnc = '0' + mccmnc[3:5]
    else:
        mnc = mccmnc[3:6]
        
    return b'5G:mnc' + mnc.encode('utf-8')  + b'.mcc' + mcc.encode('utf-8') + b'.3gppnetwork.org'    


#33.501#
#A.2
def return_kausf(plmn, autn, ck, ik):
    key = unhexlify(ck + ik)
    sqn_xor_ak = autn[0:12]
    plmn = return_5g_plmn(plmn) 
    message = unhexlify('6a') + plmn + unhexlify('00') + bytes([len(plmn)]) + unhexlify(sqn_xor_ak + '0006')
    h = HMAC.new(key, msg=message, digestmod=SHA256)
    return h.digest()[-32:]
 
 #A.4
def return_res_star(plmn, rand, res, ck, ik):
    key = unhexlify(ck + ik)
    plmn = return_5g_plmn(plmn) 
    print(plmn)
    message = unhexlify('6b') + plmn + unhexlify('00') + bytes([len(plmn)]) + unhexlify(rand + '0010' + res + '0008')
    h = HMAC.new(key, msg=message, digestmod=SHA256)
    return h.digest()[-16:]
 
 #A.5
def return_hres_star( rand, xres):
    s = unhexlify(rand) + xres
    h = SHA256.new(s)
    return h.digest()[-16:]
    
    
#A.6
def return_kseaf(plmn, kausf):
    key = kausf
    plmn = return_5g_plmn(plmn) 
    message = unhexlify('6c') + plmn + unhexlify('00') + bytes([len(plmn)]) 
    h = HMAC.new(key, msg=message, digestmod=SHA256)
    return h.digest()[-32:]

def return_kseaf_eap_aka_prime(access_network_identity, kausf):
    key = kausf
    message = unhexlify('6c') + access_network_identity + unhexlify('00') + bytes([len(access_network_identity)]) 
    h = HMAC.new(key, msg=message, digestmod=SHA256)
    return h.digest()[-32:]


#A.7
def return_kamf(supi, abba, kseaf):
    key = kseaf
    message = unhexlify('6d') + supi.encode('utf-8') + unhexlify('00') + bytes([len(supi)]) + abba + unhexlify('00') + bytes([len(abba)]) 
    h = HMAC.new(key, msg=message, digestmod=SHA256)
    return h.digest()[-32:]

    
#A.8
def algorithm_key_derivation_function(algo_type,algo_identity, kamf):
    key = kamf
    message = unhexlify('69') + bytes([algo_type]) + unhexlify('0001') + bytes([algo_identity]) + unhexlify('0001')  
    h = HMAC.new(key, msg=message, digestmod=SHA256)
    return h.digest()[-16:]


    
def return_all_possible_keys(plmn, autn, ck, ik, abba, supi, print_keys = False):
    kausf = return_kausf(plmn, autn, ck, ik)
    kseaf = return_kseaf(plmn, kausf)
    kamf = return_kamf(supi, abba, kseaf)
    nas_enc_alg1 = algorithm_key_derivation_function(1,1,kamf)
    nas_enc_alg2 = algorithm_key_derivation_function(1,2,kamf)
    nas_enc_alg3 = algorithm_key_derivation_function(1,3,kamf)    
    nas_int_alg1 = algorithm_key_derivation_function(2,1,kamf)
    nas_int_alg2 = algorithm_key_derivation_function(2,2,kamf)
    nas_int_alg3 = algorithm_key_derivation_function(2,3,kamf)      
    if print_keys == True:
        print('KAUSF', hexlify(kausf).decode('utf-8'))
        print('KSEAF', hexlify(kseaf).decode('utf-8'))
        print('KAMF', hexlify(kamf).decode('utf-8'))
        print('EEA1-KEY', hexlify(nas_enc_alg1).decode('utf-8'))
        print('EEA2-KEY', hexlify(nas_enc_alg2).decode('utf-8'))
        print('EEA3-KEY', hexlify(nas_enc_alg3).decode('utf-8'))
        print('EIA1-KEY', hexlify(nas_int_alg1).decode('utf-8'))
        print('EIA2-KEY', hexlify(nas_int_alg2).decode('utf-8'))
        print('EIA3-KEY', hexlify(nas_int_alg3).decode('utf-8'))
        
    return kausf, kseaf, kamf, nas_enc_alg1, nas_enc_alg2, nas_enc_alg3, nas_int_alg1, nas_int_alg2, nas_int_alg3


def return_all_possible_keys_eap_aka_prime(access_network_identity, kausf, abba, supi, print_keys = False):
    kseaf = return_kseaf_eap_aka_prime(access_network_identity, kausf)
    kamf = return_kamf(supi, abba, kseaf)
    nas_enc_alg1 = algorithm_key_derivation_function(1,1,kamf)
    nas_enc_alg2 = algorithm_key_derivation_function(1,2,kamf)
    nas_enc_alg3 = algorithm_key_derivation_function(1,3,kamf)    
    nas_int_alg1 = algorithm_key_derivation_function(2,1,kamf)
    nas_int_alg2 = algorithm_key_derivation_function(2,2,kamf)
    nas_int_alg3 = algorithm_key_derivation_function(2,3,kamf)      
    if print_keys == True:
        print('KSEAF', hexlify(kseaf).decode('utf-8'))
        print('KAMF', hexlify(kamf).decode('utf-8'))
        print('EEA1-KEY', hexlify(nas_enc_alg1).decode('utf-8'))
        print('EEA2-KEY', hexlify(nas_enc_alg2).decode('utf-8'))
        print('EEA3-KEY', hexlify(nas_enc_alg3).decode('utf-8'))
        print('EIA1-KEY', hexlify(nas_int_alg1).decode('utf-8'))
        print('EIA2-KEY', hexlify(nas_int_alg2).decode('utf-8'))
        print('EIA3-KEY', hexlify(nas_int_alg3).decode('utf-8'))
        
    return kseaf, kamf, nas_enc_alg1, nas_enc_alg2, nas_enc_alg3, nas_int_alg1, nas_int_alg2, nas_int_alg3


#A.9
def return_kgnb_kn3iwf(kamf, uplink_count, access_type):
    key = kamf
    message = unhexlify('6e') + struct.pack('!I',uplink_count) + unhexlify('0004') + bytes([access_type]) + unhexlify('0001') 
    h = HMAC.new(key, msg=message, digestmod=SHA256)
    return h.digest()[-32:]




# Annex B

def nas_hash_func(nas, count, dir, key, algo, bearer_id):
    sqn=bytes([count%256]) #last byte
    if algo == 1:
        return EIA1(key, count, bearer_id, dir, sqn+nas)
    elif algo ==2:
        return EIA2(key, count, bearer_id, dir, sqn+nas)
    elif algo ==3:
        return EIA3(key, count, bearer_id, dir, sqn+nas)
    else:
        return b'\x00\x00\x00\x00'
    
def nas_encrypt_func(nas, count, dir, key, algo, bearer_id):
    if algo == 1:
        return EEA1(key, count, bearer_id, dir, nas)
    elif algo ==2:
        return EEA2(key, count, bearer_id, dir, nas)
    elif algo ==3:
        return EEA3(key, count, bearer_id, dir, nas)
    else:
        return nas
        
        
#33.402 A.2 
def return_ck_prime_ik_prime(access_network, autn, ck, ik):  #autn ck and ik in hex string
    key = unhexlify(ck + ik)
    sqn_xor_ak = autn[0:12]
    message = unhexlify('20') +access_network + unhexlify('00') + bytes([len(access_network)]) + unhexlify(sqn_xor_ak + '0006') 
    h = HMAC.new(key, msg=message, digestmod=SHA256)
    ck_prime_ik_prime= h.digest()
    return ck_prime_ik_prime[:16], ck_prime_ik_prime[-16:]   