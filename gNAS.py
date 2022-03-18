import struct
import socket
from binascii import hexlify, unhexlify


_5GS_MM = 126
_5GS_SM = 46

#5GS MM Messages:

REGISTRATION_REQUEST = 65
REGISTRATION_ACCEPT = 66
REGISTRATION_COMPLETE = 67
REGISTRATION_REJECT = 68
DEREGISTRATION_REQUEST_UE_ORIGINATING = 69
DEREGISTRATION_ACCEPT_UE_ORIGINATING = 70
DEREGISTRATION_REQUEST_UE_TERMINATED = 71
DEREGISTRATION_ACCEPT_UE_TERMINATED = 72

SERVICE_REQUEST = 76
SERVICE_REJECT = 77
SERVICE_ACCEPT = 78
CONTROL_PLANE_SERVICE_REQUEST = 79

NETWORK_SLICE_SPECIFIC_AUTHENTICATION_COMMAND = 80
NETWORK_SLICE_SPECIFIC_AUTHENTICATION_COMPLETE = 81
NETWORK_SLICE_SPECIFIC_AUTHENTICATION_RESULT = 82
CONFIGURATION_UPDATE_COMMAND = 84
CONFIGURATION_UPDATE_COMPLETE = 85
AUTHENTICATION_REQUEST = 86
AUTHENTICATION_RESPONSE = 87 
AUTHENTICATION_REJECT = 88
AUTHENTICATION_FAILURE = 89
AUTHENTICATION_RESULT = 90
IDENTITY_REQUEST = 91
IDENTITY_RESPONSE = 92
SECURITY_MODE_COMMAND = 93
SECURITY_MODE_COMPLETE = 94
SECURITY_MODE_REJECT = 95

_5GMM_STATUS = 100
NOTIFICATION = 101
NOTIFICATION_RESPONSE = 102
UL_NAS_TRANSPORT = 103
DL_NAS_TRANSPORT = 104

#5GS SM Messages:

PDU_SESSION_ESTABLISHMENT_REQUEST =  193
PDU_SESSION_ESTABLISHMENT_ACCEPT = 194
PDU_SESSION_ESTABLISHMENT_REJECT = 195
PDU_SESSION_AUTHENTICATION_COMMAND = 197
PDU_SESSION_AUTHENTICATION_COMPLETE = 198
PDU_SESSION_AUTHENTICATION_RESULT = 199
PDU_SESSION_MODIFICATION_REQUEST = 201
PDU_SESSION_MODIFICATION_REJECT = 202
PDU_SESSION_MODIFICATION_COMMAND = 203
PDU_SESSION_MODIFICATION_COMPLETE = 204
PDU_SESSION_MODIFICATION_COMMAND_REJECT = 205
PDU_SESSION_RELEASE_REQUEST = 209
PDU_SESSION_RELEASE_REJECT = 210
PDU_SESSION_RELEASE_COMMAND = 211
PDU_SESSION_RELEASE_COMPLETE = 212
_5GSM_STATUS = 214


# Security header
PLAIN_5GS_NAS_MESSAGE = 0
INTEGRITY_PROTECTED = 1
INTEGRITY_PROTECTED_AND_CIPHERED = 2
INTEGRITY_PROTECTED_WITH_NEW_5GS_MAS_SECURITY_CONTEXT = 3
INTEGRITY_PROTECTED_AND_CIPHERED_WITH_NEW_5GS_MAS_SECURITY_CONTEXT = 4

#5GS mobile_identity
_5GS_MOBILE_IDENTITY_IE_TYPE_OF_IDENTITY__NO_IDENTITY = 0
_5GS_MOBILE_IDENTITY_IE_TYPE_OF_IDENTITY__SUCI = 1
_5GS_MOBILE_IDENTITY_IE_TYPE_OF_IDENTITY__5G_GUTI = 2
_5GS_MOBILE_IDENTITY_IE_TYPE_OF_IDENTITY__IMEI = 3
_5GS_MOBILE_IDENTITY_IE_TYPE_OF_IDENTITY__5G_S_TMSI = 4
_5GS_MOBILE_IDENTITY_IE_TYPE_OF_IDENTITY__IMEISV = 5
_5GS_MOBILE_IDENTITY_IE_TYPE_OF_IDENTITY__MAC_ADDRESS = 6
_5GS_MOBILE_IDENTITY_IE_TYPE_OF_IDENTITY__EUI_64 = 7


_5GS_MOBILE_IDENTITY_IE_SUPI_FORMAT__IMSI = 0
_5GS_MOBILE_IDENTITY_IE_SUPI_FORMAT__NETWORK_SPECIFIC_FORMAT = 1
_5GS_MOBILE_IDENTITY_IE_SUPI_FORMAT__GCI = 2
_5GS_MOBILE_IDENTITY_IE_SUPI_FORMAT__GLI = 3

_5GS_MOBILE_IDENTITY_IE_PROTECTION_SCHEME__NULL = 0
_5GS_MOBILE_IDENTITY_IE_PROTECTION_SCHEME__ECIES_PROFILE_A = 1
_5GS_MOBILE_IDENTITY_IE_PROTECTION_SCHEME__ECIES_PROFILE_B = 2


KAMF_DERIVATION_IS_NOT_REQUIRED = 0
KAMF_DERIVATION_IS_REQUIRED = 1

RETRANSMISSION_OF_INITIAL_NAS_NOT_REQUESTED = 0
RETRANSMISSION_OF_INITIAL_NAS_REQUESTED = 1

IMEISV_NOT_REQUESTED = 0
IMEISV_REQUESTED = 1


PAYLOAD_CONTAINER_TYPE__N1_SM_INFORMATION = 1
PAYLOAD_CONTAINER_TYPE__SMS = 2
PAYLOAD_CONTAINER_TYPE__LTE_POSITIONING_PROTOCOL = 3
PAYLOAD_CONTAINER_TYPE__SOR_TRANSPARENT_CONTAINER = 4
PAYLOAD_CONTAINER_TYPE__UE_POLICY_CONTAINER = 5
PAYLOAD_CONTAINER_TYPE__UE_PARAMETERS_UPDATE_TRANSPARENT_CONTAINER = 6
PAYLOAD_CONTAINER_TYPE__LOCATION_SERVICES_MESSAGE_CONTAINER = 7
PAYLOAD_CONTAINER_TYPE__CIOT_USER_DATA_CONTAINER = 8
PAYLOAD_CONTAINER_TYPE__MULTIPLE_PAYLOADS = 9

S_NSSAI_SST__EMBB  = 1
S_NSSAI_SST__URLLC = 2
S_NSSAI_SST__MIOT  = 3
S_NSSAI_SST__V2X   = 4

IE_INTEGRITY_PROTECTION_MAXIMUM_DATA_RATE__64_KBPS = b'\x00\x00'
IE_INTEGRITY_PROTECTION_MAXIMUM_DATA_RATE__NULL = b'\x01\x01'
IE_INTEGRITY_PROTECTION_MAXIMUM_DATA_RATE__FULL_DATA_RATE = b'\xff\xff'


IE_PDU_SESSION_TYPE__IPV4 = 1
IE_PDU_SESSION_TYPE__IPV6 = 2
IE_PDU_SESSION_TYPE__IPV4V6 = 3
IE_PDU_SESSION_TYPE__UNSTRUCTURED = 4
IE_PDU_SESSION_TYPE__ETHERNET = 5
IE_PDU_SESSION_TYPE__RESERVED = 7


IE_REQUEST_TYPE__INITIAL_REQUEST = 1
IE_REQUEST_TYPE__EXISTING_PDU_SESSION = 2
IE_REQUEST_TYPE__INITIAL_EMERGENCY_PDU_SESSION = 3
IE_REQUEST_TYPE__EXISTING_EMERGENCY_PDU_SESSION = 4
IE_REQUEST_TYPE__MODIFICATION_REQUEST = 5
IE_REQUEST_TYPE__MA_PDU_REQUEST = 6
IE_REQUEST_TYPE__RESERVED = 7

IE_5GS_REGISTRATION_TYPE__INITIAL_REGISTRATION = 1
IE_5GS_REGISTRATION_TYPE__MOBILITY_REGISTRATION_UPDATING = 2
IE_5GS_REGISTRATION_TYPE__PERIODIC_REGISTRATION_UPDATING = 3
IE_5GS_REGISTRATION_TYPE__EMERGENCY_REGISTRATION = 4
IE_5GS_REGISTRATION_TYPE__RESERVED = 7

IE_5GS_REGISTRATION_TYPE__FOR__NO_FOLLOW_ON_REQUEST_PENDING = 0
IE_5GS_REGISTRATION_TYPE__FOR__FOLLOW_ON_REQUEST_PENDING = 1


IE_5GMM_CAUSE__SYNCH_FAILURE = 21

IE_5GSM_CAUSE__REGULAR_DEACTIVATION = 36


IE_PCO_PROTOCOL_IDENTIFIER__LCP = 0xC021
IE_PCO_PROTOCOL_IDENTIFIER__PAP = 0xC023
IE_PCO_PROTOCOL_IDENTIFIER__CHAP = 0xC223
IE_PCO_PROTOCOL_IDENTIFIER__IPCP = 0x8021
IE_PCO_PROTOCOL_IDENTIFIER__P_CSCF_IPV6_ADDRESS = 0x1
IE_PCO_PROTOCOL_IDENTIFIER__IM_CN_SUBSYSTEM_SIGNALING_FLAG = 0x2
IE_PCO_PROTOCOL_IDENTIFIER__DNS_SERVER_IPV6_ADDRESS = 0x3
IE_PCO_PROTOCOL_IDENTIFIER__POLICY_CONTROL_REJECTION_CODE = 0x4
IE_PCO_PROTOCOL_IDENTIFIER__MS_SUPPORT_OF_NETWORK_REQUESTED_BEARER_CONTROL = 0x5
IE_PCO_PROTOCOL_IDENTIFIER__DSMIPV6_HOME_AGENT_ADDRESS = 0x7
IE_PCO_PROTOCOL_IDENTIFIER__DSMIPV6_HOME_AGENT_PREFIX = 0x8
IE_PCO_PROTOCOL_IDENTIFIER__DSMIPV6_IPV4_HOME_AGENT_ADDRESS = 0x9
IE_PCO_PROTOCOL_IDENTIFIER__IP_ADDRESS_ALLOCATION_VIA_NAS_SIGNALLING = 0xA
IE_PCO_PROTOCOL_IDENTIFIER__IPV4_ALLOCATION_VIA_DHCPV4 = 0xB
IE_PCO_PROTOCOL_IDENTIFIER__P_CSCF_IPV4_ADDRESS = 0xC
IE_PCO_PROTOCOL_IDENTIFIER__DNS_SERVER_IPV4_ADDRESS = 0xD
IE_PCO_PROTOCOL_IDENTIFIER__MSISDN = 0xE
IE_PCO_PROTOCOL_IDENTIFIER__IFOM_SUPPORT = 0xF
IE_PCO_PROTOCOL_IDENTIFIER__IPV4_LINK_MTU = 0x10
IE_PCO_PROTOCOL_IDENTIFIER__MS_SUPPORT_OF_LOCAL_ADDRESS_IN_TFT_INDICATOR = 0x11
IE_PCO_PROTOCOL_IDENTIFIER__P_CSCF_RE_SELECTION_SUPPORT = 0x12
IE_PCO_PROTOCOL_IDENTIFIER__NBIFOM_REQUEST_INDICATOR = 0x13
IE_PCO_PROTOCOL_IDENTIFIER__NBIFOM_MODE = 0x14
IE_PCO_PROTOCOL_IDENTIFIER__NON_IP_LINK_MTU = 0x15
IE_PCO_PROTOCOL_IDENTIFIER__APN_RATE_CONTROL_SUPPORT = 0x16
IE_PCO_PROTOCOL_IDENTIFIER__3GPP_PS_DATA_OFF_UE_STATUS = 0x17
IE_PCO_PROTOCOL_IDENTIFIER__RELIABLE_DATA_SERVICE = 0x18
IE_PCO_PROTOCOL_IDENTIFIER__ADDITIONAL_APN_RATE_CONTROL_FOR_EXCEPTION_DATA_SUPPORT_INDICATOR = 0x19


############################################################# INTERNAL USE #########################################################

#IE NAMES FOR SEARCH PURPOSES
IE_EXTENDED_PROTOCOL_DISCRIMINATOR = 1
IE_SECURITY_HEADER = 2
IE_MESSAGE_TYPE = 3
IE_MESSAGE_AUTHENTICATION_CODE = 4
IE_SEQUENCE_NUMBER = 5
IE_NAS_MESSAGE_ENCRYPTED = 6
IE_PDU_SESSION_IDENTITY = 7
IE_PROCEDURE_TRANSACTION_IDENTITY = 8



IE_5GS_REGISTRATION_RESULT = 100
IE_5G_GUTI = 101
IE_EQUIVALENT_PLMNS = 102
IE_TAI_LIST = 103
IE_ALLOWED_NSSAI = 104
IE_REJECTED_NSSAI = 105
IE_CONFIGURED_NSSAI = 106
IE_5GS_NETWORK_FEATURE_SUPPORT = 107
IE_T3512_VALUE = 108
IE_NON_3GPP_DEREGISTRATION_TIMER_VALUE = 109
IE_T3502_VALUE = 110

IE_NAS_KEY_SET_IDENTIFIER = 111
IE_ABBA = 112
IE_RAND = 113
IE_AUTN = 114
IE_EAP_MESSAGE = 115
IE_EPS_NAS_SECURITY_ALGORITHMS = 116
IE_IMEISV_REQUEST = 117
IE_ADDITIONAL_5G_SECURITY_INFORMATION = 118
IE_S1_UE_SECURITY_CAPABILITIES = 119
IE_NAS_SECURITY_ALGORITHMS = 120
IE_UE_SECURITY_CAPABILITY = 121
IE_PDU_SESSION_STATUS = 122
IE_PDU_SESSION_REACTIVATION_RESULT = 123
IE_PDU_SESSION_REACTIVATION_RESULT_ERROR = 124
IE_LADN_INFORMATION = 125
IE_MICO_INDICATION = 126
IE_NETWORK_SLICING_INDICATION = 127
IE_SERVICE_AREA_LIST = 128
IE_EMERGENCY_NUMBER_LIST = 129
IE_EXTENDED_EMERGENCY_NUMBER_LIST = 130
IE_SOR_TRANSPARENT_CONTAINER = 131
IE_NSSAI_INCLUSION_MODE = 132
IE_OPERATOR_DEFINED_ACCESS_CATEGORY_DEFINITIONS = 133
IE_5GS_DRX_PARAMETERS = 134
IE_NON_3GPP_NW_PROVIDED_POLICIES = 135
IE_EPS_BEARER_CONTEXT_STATUS = 136
IE_EXTENDED_DRX_PARAMETERS = 137
IE_T3447_VALUE = 138
IE_T3448_VALUE = 139
IE_T3324_VALUE = 140
IE_UE_RADIO_CAPABILITY_ID = 141
IE_UE_RADIO_CAPABILITY_ID_DELETION = 142
IE_PENDING_NSSAI = 143
IE_CIPHERING_KEY_DATA = 144
IE_CAG_INFORMATION_LIST = 145
IE_TRUNCATED_5G_S_TMSI_CONFIGURATION = 146
IE_WUS_ASSISTANCE_INFORMATION = 147
IE_NB_N1_MODE_DRX_PARAMETERS = 148
IE_DDN = 149
IE_PDU_SESSION_TYPE = 150
IE_SSC_MODE = 151
IE_QOS_RULES = 152
IE_SESSION_AMBR = 153
IE_5GSM_CAUSE = 154
IE_PDU_ADDRESS = 155
IE_RQ_TIMER_VALUE = 156
IE_S_NSSAI = 157
IE_ALWAYS_ON_PDU_SESSION_INDICATION = 158
IE_MAPPED_EPS_BEARER_CONTEXTS = 159
IE_QOS_FLOW_DESCRIPTIONS = 160
IE_EXTENDED_PROTOCOL_CONFIGURATIONS_OPTIONS = 161
IE_5GSM_NETWORK_FEATURE_SUPPORT = 162
IE_SERVING_PLMN_RATE_CONTROL = 163
IE_ATSSS_CONTAINER = 164
IE_CONTROL_PLANE_ONLY_INDICATION = 165
IE_IP_HEADER_COMPRESSION_CONFIGURATION = 166
IE_ETHERNET_HEADER_COMPRESSION_CONFIGURATION = 167
IE_BACK_OFF_TIMER_VALUE = 168
IE_ALLOWED_SCC_MODE = 169
IE_RE_ATTEMPT_INDICATOR = 170
IE_5GSM_CONGESTION_RE_ATTEMPT_INDICATOR = 171
IE_PAYLOAD_CONTAINER_TYPE = 172
IE_PAYLOAD_CONTAINER = 173
IE_ADDITIONAL_INFORMATION = 174
IE_5GMM_CAUSE = 175


IE_DDN__DDN = 14801



IE_ADDITIONAL_5G_SECURITY_INFORMATION__HDP = 11801
IE_ADDITIONAL_5G_SECURITY_INFORMATION__RETRANSMISSION_OF_INITIAL_NAS = 11802


IE_DECODER_5GS_TYPE_OF_IDENTITY = 40000
IE_DECODER_5GS_MCC_MNC = 40001
IE_DECODER_5GS_AMF_REGION_ID = 40002
IE_DECODER_5GS_AMF_SET_ID = 40003
IE_DECODER_5GS_AMF_POINTER = 40004
IE_DECODER_5GS_5G_TMSI = 40005


######################################################################################################################
#                                   D  E  C  O  D  E     F  U  N  C  T  I  O  N  S                                   #
######################################################################################################################


#BASE FUNCTION to be called from external modules

#only used for downlink messages
#input: nas message


def nas_decode(nas): #DONE
    nas_list = []
    if nas == None:
        return nas_list
        
    extended_protocol_discriminator = nas[0]
    nas_list.append((IE_EXTENDED_PROTOCOL_DISCRIMINATOR, extended_protocol_discriminator))
    if extended_protocol_discriminator == _5GS_MM: # 5GS_MM
    
        security_header = nas[1]
        nas_list.append((IE_SECURITY_HEADER, security_header))
        if security_header == 0: # plain nas
            nas_list.append((IE_MESSAGE_TYPE, nas[2]))
            if len(nas)>3:
                emm_list = nas_decode_5gs_mm(nas[2], nas[3:])
                nas_list += emm_list

        else:
            nas_list.append((IE_MESSAGE_AUTHENTICATION_CODE,nas[2:6]))
            nas_list.append((IE_SEQUENCE_NUMBER,nas[6]))
            nas_list.append((IE_NAS_MESSAGE_ENCRYPTED, nas[7:]))
                
    elif extended_protocol_discriminator == _5GS_SM: # 5GS_SM
        pdu_session_identity = nas[1] 
        nas_list.append((IE_PDU_SESSION_IDENTITY, pdu_session_identity))    
        nas_list.append((IE_PROCEDURE_TRANSACTION_IDENTITY, nas[2]))
        nas_list.append((IE_MESSAGE_TYPE, nas[3]))
        if len(nas)>3:
            esm_list = nas_decode_5gs_sm(nas[3], nas[4:])
            nas_list += esm_list
            #esm#
        
    return nas_list

        
        
def return_ie_list_and_pointer(packet, iei_list, pointer, iei_type, name, size=0):  #size is needed for V or TV tag type.
# TV size=0 means tag and value in one byte
# TV size= 1 means tag and 1 byte for value. return value as integer
# TV size >1 means tag and n bytes for value. return bytes in range

#V size = 1 means value in one byte return value as integer
#V size > 1 means value in n bytes. return bytes in range

    if iei_type == 'V':
        if size == 1:
            iei_list.append((name, packet[pointer]))
            pointer += 1
        else:
            iei_list.append((name, packet[pointer:pointer+size]))
            pointer += size        
    elif iei_type == 'LV':
        iei_list.append((name, packet[pointer+1:pointer+1+packet[pointer]]))
        pointer += 1+packet[pointer]  
    elif iei_type == 'LV-E':
        iei_list.append((name, packet[pointer+2:pointer+2+packet[pointer]*256+packet[pointer+1]]))
        pointer += 2+packet[pointer]*256+packet[pointer+1]
    elif iei_type == 'TV':
        if size == 0:
            iei_list.append((name, packet[pointer] % 16))
            pointer += 1
        elif size == 1:
            iei_list.append((name, packet[pointer+1]))
            pointer += 2
        else:
            iei_list.append((name, packet[pointer+1:pointer+1+size]))
            pointer += 1+size
    elif iei_type == 'TLV':
        iei_list.append((name, packet[pointer+2:pointer+2+packet[pointer+1]]))
        pointer += 2+packet[pointer+1]      
    elif iei_type == 'TLV-E':
        iei_list.append((name, packet[pointer+3:pointer+3+packet[pointer+1]*256+packet[pointer+2]]))
        pointer += 3+packet[pointer+1]*256+packet[pointer+2]    
 
    return iei_list, pointer
       
        
#-------------------------------------#
#                                     #
# 5 G S   M M  -  P r o c e d u r e s #
#                                     #
#-------------------------------------#
             
#input: message_type and next bytes of nas with ies    
def nas_decode_5gs_mm(message_type, ies):         #DONE
    ies_list = []
    if message_type == REGISTRATION_ACCEPT: 
        ies_list = nas_decode_5gs_mm_registration_accept(ies)
    elif message_type == REGISTRATION_REJECT: 
        ies_list = nas_decode_5gs_mm_registration_reject(ies)
    elif message_type == DEREGISTRATION_REQUEST_UE_TERMINATED: 
        ies_list = nas_decode_5gs_mm_deregistration_request(ies)
    elif message_type == DEREGISTRATION_ACCEPT_UE_ORIGINATING: 
        ies_list = nas_decode_5gs_mm_deregistration_accept(ies)       
    elif message_type == AUTHENTICATION_REQUEST:
        ies_list = nas_decode_5gs_mm_authentication_request(ies)
    elif message_type == AUTHENTICATION_REJECT:
        ies_list = nas_decode_5gs_mm_authentication_reject(ies)
    elif message_type == IDENTITY_REQUEST:
        ies_list = nas_decode_5gs_mm_identity_request(ies)        
    elif message_type == SECURITY_MODE_COMMAND:
        ies_list = nas_decode_5gs_mm_security_mode_command(ies)
    elif message_type == DL_NAS_TRANSPORT:
        ies_list = nas_decode_5gs_mm_dl_nas_transport(ies)
        
    return ies_list
  

def nas_decode_5gs_mm_dl_nas_transport(ies):
    ies_list, ies_size = [] , len(ies)
    ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,0,"V",IE_PAYLOAD_CONTAINER_TYPE,1)       
    ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"LV-E",IE_PAYLOAD_CONTAINER) 
    if pointer < ies_size and ies[pointer] == 0x12: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TV",IE_PDU_SESSION_IDENTITY,1) 
    if pointer < ies_size and ies[pointer] == 0x24: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_ADDITIONAL_INFORMATION)    
    if pointer < ies_size and ies[pointer] == 0x12: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TV",IE_5GMM_CAUSE,1)     
    if pointer < ies_size and ies[pointer] == 0x37: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_BACK_OFF_TIMER_VALUE)     
    return ies_list  
        
def nas_decode_5gs_mm_registration_accept(ies):  #DONE
    ies_list, ies_size = [] , len(ies)
    ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,0,"LV",IE_5GS_REGISTRATION_RESULT)
    if pointer < ies_size and ies[pointer] == 0x77: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV-E",IE_5G_GUTI)
    if pointer < ies_size and ies[pointer] == 0x4A: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_EQUIVALENT_PLMNS)
    if pointer < ies_size and ies[pointer] == 0x54: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_TAI_LIST)
    if pointer < ies_size and ies[pointer] == 0x15: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_ALLOWED_NSSAI)
    if pointer < ies_size and ies[pointer] == 0x11: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_REJECTED_NSSAI) 
    if pointer < ies_size and ies[pointer] == 0x31: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_CONFIGURED_NSSAI)
    if pointer < ies_size and ies[pointer] == 0x21: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_5GS_NETWORK_FEATURE_SUPPORT)
    if pointer < ies_size and ies[pointer] == 0x50: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_PDU_SESSION_STATUS)
    if pointer < ies_size and ies[pointer] == 0x26: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_PDU_SESSION_REACTIVATION_RESULT)
    if pointer < ies_size and ies[pointer] == 0x72: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV-E",IE_PDU_SESSION_REACTIVATION_RESULT_ERROR)
    if pointer < ies_size and ies[pointer] == 0x79: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV-E",IE_LADN_INFORMATION)
    if pointer < ies_size and ies[pointer] // 16 == 0xB: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TV",IE_MICO_INDICATION,0) 
    if pointer < ies_size and ies[pointer] // 16 == 0x9: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TV",IE_NETWORK_SLICING_INDICATION,0) 
    if pointer < ies_size and ies[pointer] == 0x27: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_SERVICE_AREA_LIST)
    if pointer < ies_size and ies[pointer] == 0x5e: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_T3512_VALUE)
    if pointer < ies_size and ies[pointer] == 0x5d: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_NON_3GPP_DEREGISTRATION_TIMER_VALUE)
    if pointer < ies_size and ies[pointer] == 0x16: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_T3502_VALUE)
    if pointer < ies_size and ies[pointer] == 0x34: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_EMERGENCY_NUMBER_LIST)
    if pointer < ies_size and ies[pointer] == 0x7a: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV-E",IE_EXTENDED_EMERGENCY_NUMBER_LIST)    
    if pointer < ies_size and ies[pointer] == 0x73: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV-E",IE_SOR_TRANSPARENT_CONTAINER)    
    if pointer < ies_size and ies[pointer] == 0x78: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV-E",IE_EAP_MESSAGE)    
    if pointer < ies_size and ies[pointer] // 16 == 0xA: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TV",IE_NSSAI_INCLUSION_MODE,0)     
    if pointer < ies_size and ies[pointer] == 0x76: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV-E",IE_OPERATOR_DEFINED_ACCESS_CATEGORY_DEFINITIONS)    
    if pointer < ies_size and ies[pointer] == 0x51: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_5GS_DRX_PARAMETERS)
    if pointer < ies_size and ies[pointer] // 16 == 0xD: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TV",IE_NON_3GPP_NW_PROVIDED_POLICIES,0) 
    if pointer < ies_size and ies[pointer] == 0x60: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_EPS_BEARER_CONTEXT_STATUS)    

    if pointer < ies_size and ies[pointer] == 0x6e: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_EXTENDED_DRX_PARAMETERS)   
    if pointer < ies_size and ies[pointer] == 0x6c: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_T3447_VALUE)   
    if pointer < ies_size and ies[pointer] == 0x6b: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_T3448_VALUE)   
    if pointer < ies_size and ies[pointer] == 0x6a: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_T3324_VALUE)   
    if pointer < ies_size and ies[pointer] == 0x67: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_UE_RADIO_CAPABILITY_ID)       
    if pointer < ies_size and ies[pointer] // 16 == 0xc: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TV",IE_UE_RADIO_CAPABILITY_ID_DELETION,0) 
    if pointer < ies_size and ies[pointer] == 0x39: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_PENDING_NSSAI)       
    if pointer < ies_size and ies[pointer] == 0x74: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV-E",IE_CIPHERING_KEY_DATA)    
    if pointer < ies_size and ies[pointer] == 0x75: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV-E",IE_CAG_INFORMATION_LIST)    
    if pointer < ies_size and ies[pointer] == 0x1b: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_TRUNCATED_5G_S_TMSI_CONFIGURATION)   
    if pointer < ies_size and ies[pointer] == 0x1c: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_WUS_ASSISTANCE_INFORMATION)   
    if pointer < ies_size and ies[pointer] == 0x29: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_NB_N1_MODE_DRX_PARAMETERS)

    
    return ies_list
    
def nas_decode_5gs_mm_registration_reject(ies):
    ies_list, ies_size = [] , len(ies)

    return ies_list

def nas_decode_5gs_mm_deregistration_request(ies):
    ies_list, ies_size = [] , len(ies)

    
    return ies_list

def nas_decode_5gs_mm_deregistration_accept(ies):
    pass #done no IEI


def nas_decode_5gs_mm_authentication_request(ies):   #DONE
    ies_list, ies_size = [] , len(ies)
    ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,0,"V",IE_NAS_KEY_SET_IDENTIFIER,1)
    ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"LV",IE_ABBA,1)
    if pointer < ies_size and ies[pointer] == 0x21: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TV",IE_RAND,16)
    if pointer < ies_size and ies[pointer] == 0x20: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_AUTN)
    if pointer < ies_size and ies[pointer] == 0x78: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV-E",IE_EAP_MESSAGE)    
    
    return ies_list
    
      
    
def nas_decode_5gs_mm_authentication_reject(ies): #DONE
    ies_list = []
    if ies[pointer] == 0x78: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,0,"TLV-E",IE_EAP_MESSAGE) 
    
    return ies_list    

def nas_decode_5gs_mm_identity_request(ies):
    ies_list = []
    ies_list.append(("identity type", ies[0] % 16))
    
    return ies_list 

def nas_decode_5gs_mm_security_mode_command(ies): #DONE
    ies_list, ies_size = [] , len(ies)
    ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,0,"V",IE_NAS_SECURITY_ALGORITHMS,1)    
    ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"V",IE_NAS_KEY_SET_IDENTIFIER,1)    
    ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"LV",IE_UE_SECURITY_CAPABILITY)     
    if pointer < ies_size and ies[pointer] // 16 == 0xE: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TV",IE_IMEISV_REQUEST,0) 
    if pointer < ies_size and ies[pointer] == 0x57: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TV",IE_EPS_NAS_SECURITY_ALGORITHMS,1) 
    if pointer < ies_size and ies[pointer] == 0x36: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_ADDITIONAL_5G_SECURITY_INFORMATION)
    if pointer < ies_size and ies[pointer] == 0x78: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV-E",IE_EAP_MESSAGE)  
    if pointer < ies_size and ies[pointer] == 0x38: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_ABBA)
    if pointer < ies_size and ies[pointer] == 0x19: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_S1_UE_SECURITY_CAPABILITIES)

    return ies_list

        
        
#-------------------------------------#
#                                     #
# 5 G S   S M  -  P r o c e d u r e s #
#                                     #
#-------------------------------------#      
         
#inputs: message_type and next bytes of nas with ies
def nas_decode_5gs_sm(message_type, ies):
    ies_list = []
    if message_type == PDU_SESSION_ESTABLISHMENT_ACCEPT:
        ies_list = nas_decode_5gs_sm_pdu_session_establishment_accept(ies)
    elif message_type == PDU_SESSION_ESTABLISHMENT_REJECT:
        ies_list = nas_decode_5gs_sm_pdu_session_establishment_reject(ies)

    return ies_list
    
    
def nas_decode_5gs_sm_pdu_session_establishment_accept(ies):
    ies_list, ies_size = [] , len(ies)
    ies_list.append((IE_PDU_SESSION_TYPE, ies[0]%16))  
    ies_list.append((IE_SSC_MODE, ies[0]//16))      
    ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,1,"LV-E",IE_QOS_RULES)  
    ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"LV",IE_SESSION_AMBR)  
    if pointer < ies_size and ies[pointer] == 0x59: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TV",IE_5GSM_CAUSE,1)     
    if pointer < ies_size and ies[pointer] == 0x29: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_PDU_ADDRESS)    
    if pointer < ies_size and ies[pointer] == 0x56: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TV",IE_RQ_TIMER_VALUE,1) 
    if pointer < ies_size and ies[pointer] == 0x22: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_S_NSSAI)    
    if pointer < ies_size and ies[pointer] // 16 == 0x8: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TV",IE_ALWAYS_ON_PDU_SESSION_INDICATION,0)
    if pointer < ies_size and ies[pointer] == 0x75: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV-E",IE_MAPPED_EPS_BEARER_CONTEXTS) 
    if pointer < ies_size and ies[pointer] == 0x78: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV-E",IE_EAP_MESSAGE) 
    if pointer < ies_size and ies[pointer] == 0x79: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV-E",IE_QOS_FLOW_DESCRIPTIONS) 
    if pointer < ies_size and ies[pointer] == 0x7B: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV-E",IE_EXTENDED_PROTOCOL_CONFIGURATIONS_OPTIONS)     
    if pointer < ies_size and ies[pointer] == 0x25: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_DDN) 
    if pointer < ies_size and ies[pointer] == 0x17: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_5GSM_NETWORK_FEATURE_SUPPORT) 
    if pointer < ies_size and ies[pointer] == 0x18: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_SERVING_PLMN_RATE_CONTROL)     
    if pointer < ies_size and ies[pointer] == 0x77: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV-E",IE_ATSSS_CONTAINER) 
    if pointer < ies_size and ies[pointer] // 16 == 0xC: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TV",IE_CONTROL_PLANE_ONLY_INDICATION,0)
    if pointer < ies_size and ies[pointer] == 0x66: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_IP_HEADER_COMPRESSION_CONFIGURATION)
    if pointer < ies_size and ies[pointer] == 0x1F: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_ETHERNET_HEADER_COMPRESSION_CONFIGURATION)    
    return ies_list            


def nas_decode_5gs_sm_pdu_session_establishment_reject(ies):
    ies_list, ies_size = [] , len(ies)
    ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,0,"V",IE_5GSM_CAUSE,1) 
    if pointer < ies_size and ies[pointer] == 0x37: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_BACK_OFF_TIMER_VALUE) 
    if pointer < ies_size and ies[pointer] // 16 == 0xF: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TV",IE_ALLOWED_SCC_MODE,0)    
    if pointer < ies_size and ies[pointer] == 0x78: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV-E",IE_EAP_MESSAGE)
    if pointer < ies_size and ies[pointer] == 0x7B: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV-E",IE_EXTENDED_PROTOCOL_CONFIGURATIONS_OPTIONS)     
    if pointer < ies_size and ies[pointer] == 0x1D: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_RE_ATTEMPT_INDICATOR) 
    if pointer < ies_size and ies[pointer] == 0x61: ies_list, pointer = return_ie_list_and_pointer(ies,ies_list,pointer,"TLV",IE_5GSM_CONGESTION_RE_ATTEMPT_INDICATOR)     
    return ies_list 

    
######################################################################################################################
#                                   E  N  C  O  D  E     F  U  N  C  T  I  O  N  S                                   #
######################################################################################################################

#[(protocol_discriminator, security_header), (iei1, format, value), (iei2, format, value), etc...]
#  iei = 0 if mandatory. i[2] in bytes format
#  other values as 0x19. i[2] in bytes format
#  if half byte it should be like 0xF. the other part i[2] is in decimal
#
#input nas_list with sequencial   
def nas_encode(nas_list):    
    nas = b''
    extended_protocol_discriminator = nas_list[0][0]
    security_header = nas_list[0][1]
    nas += bytes([extended_protocol_discriminator])
    nas += bytes([security_header])
    for i in range(1,len(nas_list)):
        if nas_list[i][0] == 0:
            if nas_list[i][1] == 'V':
                nas += nas_list[i][2]
            elif nas_list[i][1] == 'LV':
                nas += bytes([len(nas_list[i][2])]) + nas_list[i][2]
            elif nas_list[i][1] == 'LV-E':
                nas += bytes([len(nas_list[i][2])//256]) + bytes([len(nas_list[i][2])%256]) + nas_list[i][2]
        else:
            if nas_list[i][1] == "TV":
                if nas_list[i][0] < 16: #one hex symbol is just one byte len. always TV. Value in decimal
                    nas += bytes([(nas_list[i][0]<<4) + nas_list[i][2]])
                else:
                    nas += bytes([nas_list[i][0]]) + nas_list[i][2]
            if nas_list[i][1] == "TLV":
                nas += bytes([nas_list[i][0]]) + bytes([len(nas_list[i][2])]) + nas_list[i][2]    
            if nas_list[i][1] == "TLV-E":
                nas += bytes([nas_list[i][0]]) + bytes([len(nas_list[i][2])//256]) + bytes([len(nas_list[i][2])%256]) + nas_list[i][2]     
    
    return nas
    
    
## Messages: ##   MM 
    
def nas_security_protected_nas_message(security_header,message_authentication_code, count, nas_message):
    emm_list = []
    emm_list.append((_5GS_MM,security_header))  # protocol discriminator / 
    emm_list.append((0,'V',message_authentication_code)) # message type: authentication response
    emm_list.append((0,'V',bytes([count%256])))
    emm_list.append((0,'V',nas_message))
    return nas_encode(emm_list)

def nas_5gs_mm_registration_request(mcc_mnc, imsi, _5gs_registration_type,nas_key_set_identifier):
    emm_list = []
    emm_list.append((_5GS_MM,PLAIN_5GS_NAS_MESSAGE))
    emm_list.append((0,'V',bytes([REGISTRATION_REQUEST])))
    emm_list.append((0,'V',bytes([(nas_key_set_identifier<<4) + _5gs_registration_type])))
    emm_list.append((0,'LV-E',encode_suci_null_scheme(mcc_mnc,imsi)))
    emm_list.append((0x10,'TLV',b'\x06')) 
    emm_list.append((0x2E,'TLV',b'\x80\x20'))  
    return nas_encode(emm_list)

def nas_5gs_mm_authentication_response(res= None, eap=None):
    emm_list = []
    emm_list.append((_5GS_MM,PLAIN_5GS_NAS_MESSAGE))
    emm_list.append((0,'V',bytes([AUTHENTICATION_RESPONSE])))
    if res is not None: emm_list.append((0x2D,'TLV',res))    
    if eap is not None: emm_list.append((0x78,'TLV-E',eap))
    return nas_encode(emm_list)


def nas_5gs_mm_authentication_failure(cause, auts):
    emm_list = []
    emm_list.append((_5GS_MM,PLAIN_5GS_NAS_MESSAGE))
    emm_list.append((0,'V',bytes([AUTHENTICATION_FAILURE])))
    emm_list.append((0,'V',bytes([cause])))    
    emm_list.append((0x30,'TLV',auts))    
    return nas_encode(emm_list)
    
def nas_5gs_mm_security_mode_complete(imeisv, nas):
    emm_list = []
    emm_list.append((_5GS_MM,PLAIN_5GS_NAS_MESSAGE))
    emm_list.append((0,'V',bytes([SECURITY_MODE_COMPLETE])))
    if imeisv is not None: emm_list.append((0x77,'TLV-E',encode_imei_imeisv(_5GS_MOBILE_IDENTITY_IE_TYPE_OF_IDENTITY__IMEISV,imeisv)))
    if nas is not None: emm_list.append((0x71, 'TLV-E', nas))
    return nas_encode(emm_list)

def nas_5gs_mm_registration_complete():
    emm_list = []
    emm_list.append((_5GS_MM,PLAIN_5GS_NAS_MESSAGE))
    emm_list.append((0,'V',bytes([REGISTRATION_COMPLETE])))
    return nas_encode(emm_list)
    
    
def nas_5gs_mm_ul_nas_transport(payload_type, payload, pdu_session_id, request_type, s_nssai, ddn):
    emm_list = []
    emm_list.append((_5GS_MM,PLAIN_5GS_NAS_MESSAGE))
    emm_list.append((0,'V',bytes([UL_NAS_TRANSPORT])))
    emm_list.append((0,'V',bytes([payload_type])))
    emm_list.append((0,'LV-E',payload))   
    if pdu_session_id is not None: emm_list.append((0x12,'TV',bytes([pdu_session_id]))) 
    if request_type is not None: emm_list.append((0x8,'TV',request_type))
    if s_nssai is not None: emm_list.append((0x22,'TLV',s_nssai))     
    if ddn is not None: emm_list.append((0x25,'TLV',ddn))     
    return nas_encode(emm_list)
    
    
## Messages: ##   SM     
    
    
def nas_5gs_sm_pdu_session_establishment_request(pdu_session_id,pti,integrity_protection,pdu_session_type,always_on,extended_protocol_configurations):
    emm_list = []
    emm_list.append((_5GS_SM,pdu_session_id))
    emm_list.append((0,'V',bytes([pti])))
    emm_list.append((0,'V',bytes([PDU_SESSION_ESTABLISHMENT_REQUEST])))
    emm_list.append((0,'V',integrity_protection))  #2 bytes  
    
    if pdu_session_type is not None: emm_list.append((0x9,'TV',pdu_session_type)) 
    if always_on is not None: emm_list.append((0xB,'TV',always_on))
    if extended_protocol_configurations is not None: emm_list.append((0x7B,'TLV-E',extended_protocol_configurations))         
    return nas_encode(emm_list)    


def nas_5gs_sm_pdu_session_release_request(pdu_session_id,pti,_5gsm_cause,extended_protocol_configurations):
    emm_list = []
    emm_list.append((_5GS_SM,pdu_session_id))
    emm_list.append((0,'V',bytes([pti])))
    emm_list.append((0,'V',bytes([PDU_SESSION_RELEASE_REQUEST])))  
    
    if _5gsm_cause is not None: emm_list.append((0x59,'TV',bytes([_5gsm_cause]))) 
    if extended_protocol_configurations is not None: emm_list.append((0x7B,'TLV-E',extended_protocol_configurations))         
    return nas_encode(emm_list)    
        
    
    
    

######################################################################################################################
######################################################################################################################
######################################################################################################################
######################################################################################################################








######################################################################################################################
######################################################################################################################
######################################################################################################################
#
#  specific Fucntions to decode some NAS IEI
#
#

def decode_additional_5g_security_information(iei): #DONE
    iei_list = []
    hdp = iei[0] % 4 // 2
    retrans_initial_nas = iei[0] % 2
    iei_list.append((IE_ADDITIONAL_5G_SECURITY_INFORMATION__HDP, hdp))
    iei_list.append((IE_ADDITIONAL_5G_SECURITY_INFORMATION__RETRANSMISSION_OF_INITIAL_NAS, retrans_initial_nas))     
    return iei_list


def decode_5gs_mobile_identity(iei): #DONE FOR 5G-GUTI
    iei_list = []
    type_of_identity = iei[0] % 8
    iei_list.append((IE_DECODER_5GS_TYPE_OF_IDENTITY, type_of_identity))
    if type_of_identity == _5GS_MOBILE_IDENTITY_IE_TYPE_OF_IDENTITY__5G_GUTI: #5g guti
        mcc = str(iei[1]%16) + str(iei[1]//16) + str(iei[2]%16)
        if iei[2] // 16 == 15: #1111
            mnc = str(iei[3]%16) + str(iei[3]//16)
        else:
            mnc = str(iei[3]%16) + str(iei[3]//16) + str(iei[2]//16)
        iei_list.append((IE_DECODER_5GS_MCC_MNC,int(mcc + mnc)))
        iei_list.append((IE_DECODER_5GS_AMF_REGION_ID, iei[4]))
        amf_region_id = (iei[5]<<2) + (iei[6]>>6)
        iei_list.append((IE_DECODER_5GS_AMF_SET_ID, amf_region_id))    
        iei_list.append((IE_DECODER_5GS_AMF_POINTER, iei[6]%64))    
        iei_list.append((IE_DECODER_5GS_5G_TMSI, iei[7:11]))
    return iei_list
    

def decode_pdu_address(iei): #DONE
    iei_list = []
    pdu_type_value = iei[0] % 8
    iei_list.append((IE_PDU_SESSION_TYPE, pdu_type_value))
    if pdu_type_value == IE_PDU_SESSION_TYPE__IPV4: # ipv4
        iei_list.append((IE_PDU_SESSION_TYPE__IPV4,socket.inet_ntop(socket.AF_INET, iei[1:1+4])))
    elif pdu_type_value == IE_PDU_SESSION_TYPE__IPV6: # ipv6
        iei_list.append((IE_PDU_SESSION_TYPE__IPV6, socket.inet_ntop(socket.AF_INET6, iei[1:1+8] + 8*b'\x00')))
    elif pdu_type_value == IE_PDU_SESSION_TYPE__IPV4V6: # ipv4v6
        iei_list.append((IE_PDU_SESSION_TYPE__IPV6, socket.inet_ntop(socket.AF_INET6, iei[1:1+8] + 8*b'\x00')))
        iei_list.append((IE_PDU_SESSION_TYPE__IPV4,socket.inet_ntop(socket.AF_INET, iei[9:9+4])))
    return iei_list

def decode_ddn(byteArray): #DONE
    a = []
    pos = 0
    while pos < len(byteArray):
        i = int(byteArray[pos])
        for x in range(pos+1, pos+1+i):
            a.append(chr(byteArray[x]))

        a.append(".")
        pos = pos+1+i

    return [(IE_DDN__DDN, ''.join(a)[:-1])]
    
    
    
def decode_pco(iei):
    iei_list = []
    position = 1
    while position < len(iei):
        protocol_id = struct.unpack("!H", iei[position:position+2])[0]
        length = iei[position+2]
        iei_list.append((protocol_id, iei[position+3:position+3+length]))
        position += 3 + length
    
    return iei_list

######################################################################################################################
######################################################################################################################
######################################################################################################################
#
#  specific Fucntions to encode some NAS IEI
#
#
    
#related to 5GS Mobile Identity:    

def encode_pco(session_type):
    iei_list = []
    if session_type == IE_PDU_SESSION_TYPE__IPV4:
        iei_list.append((IE_PCO_PROTOCOL_IDENTIFIER__DNS_SERVER_IPV4_ADDRESS,None))
    elif session_type == IE_PDU_SESSION_TYPE__IPV6:
        iei_list.append((IE_PCO_PROTOCOL_IDENTIFIER__DNS_SERVER_IPV6_ADDRESS,None))        
    elif session_type == IE_PDU_SESSION_TYPE__IPV4V6:
        iei_list.append((IE_PCO_PROTOCOL_IDENTIFIER__DNS_SERVER_IPV4_ADDRESS,None))
        iei_list.append((IE_PCO_PROTOCOL_IDENTIFIER__DNS_SERVER_IPV6_ADDRESS,None))         
    return encode_pco_generic(iei_list)

def encode_pco_generic(iei_list): #return pco payload in bytes
    pco = b'\x80'
    for i in iei_list:
        pco += struct.pack("!H", i[0])
        if i[1] is None:
            pco += b'\x00'
        else:
            pco += bytes([len(i[1])]) + i[1]
    return pco

def encode_ddn(ddn):
    ddn_bytes = bytes()
    ddn_l = ddn.split(".") 
    for word in ddn_l:
        ddn_bytes += struct.pack("!B", len(word)) + word.encode()
    return ddn_bytes


def encode_5g_guti(mcc_mnc, amf_region_id, amf_set_id, amf_pointer, _5g_tmsi):
    guti = struct.pack("!B", (15<<4) + _5GS_MOBILE_IDENTITY_IE_TYPE_OF_IDENTITY__5G_GUTI)
    
    if len(mcc_mnc) == 5: mcc_mnc += 'f'
    guti += unhexlify(mcc_mnc[1] + mcc_mnc[0] + mcc_mnc[5] +mcc_mnc[2]+ mcc_mnc[4]+ mcc_mnc[3])
    guti += struct.pack("!B", amf_region_id)
    guti += struct.pack("!H", (amf_set_id<<6) + amf_pointer)
    guti += struct.pack("!L", _5g_tmsi)
    return guti

def encode_msin(msin): #DONE
    if len(msin) % 2 == 1: msin += 'f'
    aux = b''
    for i in range(0,len(msin),2):
        aux += unhexlify(msin[i+1] + msin[i])
    return aux

def encode_suci_supi(mcc_mnc, type_identity, supi_format, ri1, ri2, ri3, ri4, protection_scheme, hnp_key_identifier, output):  # DONE #output could by schemme output or msin in case of null scheme
    suci_supi = b''
    suci_supi += struct.pack("!B", (supi_format<<4) + type_identity)
    if len(mcc_mnc) == 5: mcc_mnc += 'f'
    suci_supi += unhexlify(mcc_mnc[1] + mcc_mnc[0] + mcc_mnc[5] +mcc_mnc[2]+ mcc_mnc[4]+ mcc_mnc[3])    
    suci_supi += struct.pack("!B", (ri2<<4) + ri1)
    suci_supi += struct.pack("!B", (ri4<<4) + ri3)    
    suci_supi += struct.pack("!B", protection_scheme) 
    suci_supi += struct.pack("!B", hnp_key_identifier)    
    suci_supi += output    
    return suci_supi    
  
def encode_suci_null_scheme(mcc_mnc, imsi): #DONE
    return encode_suci_supi(mcc_mnc, _5GS_MOBILE_IDENTITY_IE_TYPE_OF_IDENTITY__SUCI,
        _5GS_MOBILE_IDENTITY_IE_SUPI_FORMAT__IMSI,0, 0xF, 0xF, 0xF,
        _5GS_MOBILE_IDENTITY_IE_PROTECTION_SCHEME__NULL,0,encode_msin(imsi[len(mcc_mnc):]))
        
def encode_imei_imeisv(type_identity,imei): #DONE
    if len(imei) % 2 ==1: 
        type_identity += 8
    else:
        imei += 'f'
    imei_imeisv = struct.pack("!B", (int(imei[0])<<4) +type_identity) 
    for i in range(1,len(imei),2):
        imei_imeisv += unhexlify(imei[i+1] + imei[i])
    return imei_imeisv
    

def encode_s_nssai(sst,ssd=None, mapped_hplmn_sst = None, mapped_hplmn_ssd=None):
    s_nssai = bytes([sst])
    if ssd is not None: s_nssai += struct.pack("!I",ssd)[1:] 
    if mapped_hplmn_sst is not None: s_nssai += bytes([mapped_hplmn_sst])  
    if mapped_hplmn_ssd is not None: s_nssai += struct.pack("!I",mapped_hplmn_ssd)[1:]    
    return s_nssai
    
   

def encode_5gs_registration_type(_for, _5gs_registration_type_value):
    return 8*_for + _5gs_registration_type_value    
    
############################################################
############################################################    
    
def get_nas_ie_by_name(nas_list, name):
    for i in nas_list:
        if i[0] == name:
            return i[1]
    return None

def get_pco_element_by_name(pco_list, name):
    pco_return_list = []
    for i in pco_list:
        if i[0] == name:
            pco_return_list.append(i[1])
    return pco_return_list

def get_ip_str_from_ip_bytes(ip_list):
    return_list = []
    for i in ip_list:
        if len(i) == 4:
            return_list.append(socket.inet_ntop(socket.AF_INET,i))
        elif len(i) == 16:
            return_list.append(socket.inet_ntop(socket.AF_INET6,i))
    return return_list
  