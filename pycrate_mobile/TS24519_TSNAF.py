# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2020. Benoit Michau. P1Sec.
# *
# * This library is free software; you can redistribute it and/or
# * modify it under the terms of the GNU Lesser General Public
# * License as published by the Free Software Foundation; either
# * version 2.1 of the License, or (at your option) any later version.
# *
# * This library is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# * Lesser General Public License for more details.
# *
# * You should have received a copy of the GNU Lesser General Public
# * License along with this library; if not, write to the Free Software
# * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, 
# * MA 02110-1301  USA
# *
# *--------------------------------------------------------
# * File Name : pycrate_mobile/TS24519_TSNAF.py
# * Created : 2020-08-19
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

#__all__ = [
#    ]

#------------------------------------------------------------------------------#
# 3GPP TS 24.519:
# Time-Sensitive Networking (TSN) Application Function (AF) to Device-Side TSN Translator (DS-TT) 
# and Network-Side TSN Translator (NW-TT) protocol aspects
# release 16 (g10)
#------------------------------------------------------------------------------#

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *

from .TS24007       import *


# TODO: implement IE from 9.6 to 9.11 and additional IE required for 
# EthPortParam and BridgeParam

#------------------------------------------------------------------------------#
# Ethernet port management service message type
# TS 24.519, section 9.1
#------------------------------------------------------------------------------#

TSNAFEthPortMsgType_dict = {
    1 : 'MANAGE ETHERNET PORT COMMAND',
    2 : 'MANAGE ETHERNET PORT COMPLETE',
    3 : 'ETHERNET PORT MANAGEMENT NOTIFY',
    4 : 'ETHERNET PORT MANAGEMENT NOTIFY ACK',
    5 : 'ETHERNET PORT MANAGEMENT NOTIFY COMPLETE',
    6 : 'ETHERNET PORT MANAGEMENT CAPABILITY'
    }


#------------------------------------------------------------------------------#
# Ethernet port management list
# TS 24.519, section 9.2
#------------------------------------------------------------------------------#

EthPortMgmtOpCode_dict = {
    1 : 'Get capabilities',
    2 : 'Read parameter',
    3 : 'Set parameter',
    4 : 'Subscribe-notify for parameter',
    5 : 'Unsubscribe for parameter'
    }

EthPortParamName_dict = {
    0x01 : 'txPropagationDelay',
    0x02 : 'Traffic class table',
    0x03 : 'GateEnabled',
    0x04 : 'AdminBaseTime',
    0x05 : 'AdminControlListLength',
    0x06 : 'AdminControlList',
    0x07 : 'AdminCycleTime',
    0x08 : 'Tick granularity',
    0x40 : 'lldpV2PortConfigAdminStatusV2',
    0x41 : 'lldpV2LocChassisIdSubtype',
    0x42 : 'lldpV2LocChassisId',
    0x43 : 'lldpV2MessageTxInterval',
    0x44 : 'lldpV2MessageTxHoldMultiplier',
    0x60 : 'lldpV2LocPortIdSubtype',
    0x61 : 'lldpV2LocPortId',
    0xA0 : 'lldpV2RemChassisIdSubtype',
    0xA1 : 'lldpV2RemChassisId',
    0xA2 : 'lldpV2RemPortIdSubtype',
    0xA3 : 'lldpV2RemPortId',
    0xA4 : 'lldpTTL',
    0xE0 : 'Stream filter instance table',
    0xE1 : 'Stream gate instance table'
    }


class EthPortParam(Envelope):
    _GEN = (
        Uint16('Name', val=1, dic=EthPortParamName_dict),
        Uint16('Len'),
        Buf('Value', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_valauto(lambda: self[2].get_len())
        self[2].set_blauto(lambda: self[1].get_val()<<3)


class EthPortMgmtOp(Envelope):
    _GEN = (
        Uint8('Code', val=1, dic=EthPortMgmtOpCode_dict),
        Alt('', GEN={
            1: Buf('none', bl=0),
            2: Uint16('ParamName', val=1, dic=EthPortParamName_dict),
            3: EthPortParam('Param'),
            4: Uint16('ParamName', val=1, dic=EthPortParamName_dict),
            5: Uint16('ParamName', val=1, dic=EthPortParamName_dict),
            },
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()[0].get_val())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_transauto(lambda: True if self[0].get_val() == 1 else False)


class EthPortMgmtList(Sequence):
    _GEN = EthPortMgmtOp()


#------------------------------------------------------------------------------#
# Ethernet port management capability
# TS 24.519, section 9.3
#------------------------------------------------------------------------------#

class EthPortMgmtCap(Array):
    _GEN = Uint16('ParamName', val=1, dic=EthPortParamName_dict)


#------------------------------------------------------------------------------#
# Ethernet port status
# TS 24.519, section 9.4
#------------------------------------------------------------------------------#

EthPortParamErrCause_dict = {
    1   : 'Ethernet port parameter not supported',
    2   : 'Invalid Ethernet port parameter value',
    111 : 'Protocol error, unspecified'
    }


class EthPortParamErr(Envelope):
    _GEN = (
        Uint16('Name', val=1, dic=EthPortParamName_dict),
        Uint8('Cause', val=1, dic=EthPortParamErrCause_dict)
        )


class EthPortStat(Envelope):
    _GEN = (
        Uint8('EthPortStatNum'),
        Sequence('EthPortStat', GEN=EthPortParam()),
        Uint8('EthPortErrNum'),
        Sequence('EthPortErr', GEN=EthPortParamErr())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_num())
        self[1].set_numauto(lambda: self[0].get_val())
        self[2].set_valauto(lambda: self[3].get_num())
        self[3].set_numauto(lambda: self[2].get_val())


#------------------------------------------------------------------------------#
# Ethernet port update result
# TS 24.519, section 9.5
#------------------------------------------------------------------------------#

class EthPortUpdRes(Envelope):
    _GEN = (
        Uint8('EthPortUpdNum'),
        Sequence('EthPortUpd', GEN=EthPortParam()),
        Uint8('EthPortErrNum'),
        Sequence('EthPortErr', GEN=EthPortParamErr())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_num())
        self[1].set_numauto(lambda: self[0].get_val())
        self[2].set_valauto(lambda: self[3].get_num())
        self[3].set_numauto(lambda: self[2].get_val())


#------------------------------------------------------------------------------#
# Bridge management service message type
# TS 24.519, section 9.5A
#------------------------------------------------------------------------------#

TSNAFBridgeMsgType_dict = {
    1 : 'MANAGE BRIDGE COMMAND',
    2 : 'MANAGE BRIDGE COMPLETE',
    3 : 'BRIDGE MANAGEMENT NOTIFY',
    4 : 'BRIDGE MANAGEMENT ACK'
    }


#------------------------------------------------------------------------------#
# Bridge management list
# TS 24.519, section 9.5B
#------------------------------------------------------------------------------#

BridgeMgmtOpCode_dict = {
    1 : 'Get capabilities',
    2 : 'Read parameter',
    3 : 'Set parameter',
    4 : 'Subscribe-notify for parameter',
    5 : 'Unsubscribe for parameter'
    }

BridgeParamName_dict = {
    0x01 : 'Bridge Address',
    0x02 : 'Bridge Name',
    0x03 : 'Bridge ID',
    0x10 : 'Chassis ID subtype',
    0x11 : 'Chassis ID',
    0x12 : 'Static filtering entries',
    0x20 : 'lldpV2PortConfigAdminStatusV2',
    0x21 : 'lldpV2LocChassisIdSubtype',
    0x22 : 'lldpV2LocChassisId',
    0x23 : 'lldpV2MessageTxInterval',
    0x24 : 'lldpV2MessageTxHoldMultiplier',
    0x50 : 'DS-TT port neighbor discovery configuration for DS-TT ports',
    0x51 : 'Discovered neighbor information for DS-TT ports',
    0x70 : 'PSFPMaxStreamFilterInstances',
    0x71 : 'PSFPMaxStreamGateInstances',
    0x72 : 'PSFPMaxFlowMeterInstances',
    0x73 : 'PSFPMaxStreamFilterInstances'
    }


class BridgeParam(Envelope):
    _GEN = (
        Uint16('Name', val=1, dic=BridgeParamName_dict),
        Uint16('Len'),
        Buf('Value', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_valauto(lambda: self[2].get_len())
        self[2].set_blauto(lambda: self[1].get_val()<<3)


class BridgeMgmtOp(Envelope):
    _GEN = (
        Uint8('Code', val=1, dic=BridgeMgmtOpCode_dict),
        Alt('', GEN={
            1: Buf('none', bl=0),
            2: Uint16('ParamName', val=1, dic=BridgeParamName_dict),
            3: BridgeParam('Param'),
            4: Uint16('ParamName', val=1, dic=BridgeParamName_dict),
            5: Uint16('ParamName', val=1, dic=BridgeParamName_dict),
            },
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()[0].get_val())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_transauto(lambda: True if self[0].get_val() == 1 else False)


class BridgeMgmtList(Sequence):
    _GEN = BridgeMgmtOp()


#------------------------------------------------------------------------------#
# Bridge management capability
# TS 24.519, section 9.5C
#------------------------------------------------------------------------------#

class BridgeMgmtCap(Array):
    _GEN = Uint16('ParamName', val=1, dic=BridgeParamName_dict)


#------------------------------------------------------------------------------#
# Bridge status
# TS 24.519, section 9.5D
#------------------------------------------------------------------------------#


BridgeParamErrCause_dict = {
    1   : 'Bridge parameter not supported',
    2   : 'Invalid Bridge parameter value',
    111 : 'Protocol error, unspecified'
    }


class BridgeParamErr(Envelope):
    _GEN = (
        Uint16('Name', val=1, dic=BridgeParamName_dict),
        Uint8('Cause', val=1, dic=BridgeParamErrCause_dict)
        )


class BridgeStat(Envelope):
    _GEN = (
        Uint8('BridgeStatNum'),
        Sequence('BridgeStat', GEN=BridgeParam()),
        Uint8('BridgeErrNum'),
        Sequence('BridgeErr', GEN=BridgeParamErr())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_num())
        self[1].set_numauto(lambda: self[0].get_val())
        self[2].set_valauto(lambda: self[3].get_num())
        self[3].set_numauto(lambda: self[2].get_val())


#------------------------------------------------------------------------------#
# Bridge update result
# TS 24.519, section 9.5E
#------------------------------------------------------------------------------#

class BridgeUpdRes(Envelope):
    _GEN = (
        Uint8('BridgeUpdNum'),
        Sequence('BridgeUpd', GEN=BridgeParam()),
        Uint8('BridgeErrNum'),
        Sequence('BridgeErr', GEN=BridgeParamErr())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_num())
        self[1].set_numauto(lambda: self[0].get_val())
        self[2].set_valauto(lambda: self[3].get_num())
        self[3].set_numauto(lambda: self[2].get_val())


#------------------------------------------------------------------------------#
# Manage Ethernet port command
# TS 24.519, section 8.1
#------------------------------------------------------------------------------#

class ManageEthPortCommand(Layer3E):
    _GEN = (
        Uint8('Type', val=1, dic=TSNAFEthPortMsgType_dict),
        Type6LVE('EthPortMgmtList', val={'V':b''}, IE=EthPortMgmtList())
        )


#------------------------------------------------------------------------------#
# Manage Ethernet port complete
# TS 24.519, section 8.2
#------------------------------------------------------------------------------#

class ManageEthPortComplete(Layer3E):
    _GEN = (
        Uint8('Type', val=2, dic=TSNAFEthPortMsgType_dict),
        Type6TLVE('EthPortMgmtCap', val={'T':0x70, 'V':b'\0\0'}, IE=EthPortMgmtCap()),
        Type6TLVE('EthPortStat', val={'T':0x71, 'V':b'\0\0'}, IE=EthPortStat()),
        Type6TLVE('EthPortUpdRes', val={'T':0x72, 'V':b'\0\0'}, IE=EthPortUpdRes())
        )


#------------------------------------------------------------------------------#
# Ethernet port management notify
# TS 24.519, section 8.3
#------------------------------------------------------------------------------#

class EthPortMgmtNotif(Layer3E):
    _GEN = (
        Uint8('Type', val=3, dic=TSNAFEthPortMsgType_dict),
        Type6LVE('EthPortStat', val={'V':b'\0\0'}, IE=EthPortStat())
        )


#------------------------------------------------------------------------------#
# Ethernet port management notify ack
# TS 24.519, section 8.4
#------------------------------------------------------------------------------#

class EthPortMgmtNotifAck(Layer3E):
    _GEN = (
        Uint8('Type', val=4, dic=TSNAFEthPortMsgType_dict),
        )


#------------------------------------------------------------------------------#
# Ethernet port management notify complete
# TS 24.519, section 8.5
#------------------------------------------------------------------------------#

class EthPortMgmtNotifComplete(Layer3E):
    _GEN = (
        Uint8('Type', val=5, dic=TSNAFEthPortMsgType_dict),
        )


#------------------------------------------------------------------------------#
# Ethernet port management capability
# TS 24.519, section 8.6
#------------------------------------------------------------------------------#

class EthPortMgmtCap(Layer3E):
    _GEN = (
        Uint8('Type', val=6, dic=TSNAFEthPortMsgType_dict),
        Type6LVE('EthPortMgmtCap', val={'V':b'\0\0'}, IE=EthPortMgmtCap())
        )


#------------------------------------------------------------------------------#
# 5G TSN-AF Ethernet Port Management dispatcher
#------------------------------------------------------------------------------#

FGTSNAFEthPortTypeClasses = {
    1 : ManageEthPortCommand,
    2 : ManageEthPortComplete,
    3 : EthPortMgmtNotif,
    4 : EthPortMgmtNotifAck,
    5 : EthPortMgmtNotifComplete,
    6 : EthPortMgmtCap
    }

def get_5gtsnaf_ethport_msg_instances():
    return {k: FGTSNAFEthPortTypeClasses[k]() for k in FGTSNAFEthPortTypeClasses}


#------------------------------------------------------------------------------#
# Manage Bridge command
# TS 24.519, section 8.7
#------------------------------------------------------------------------------#

class ManageBridgeCommand(Layer3E):
    _GEN = (
        Uint8('Type', val=1, dic=TSNAFBridgeMsgType_dict),
        Type6LVE('BridgeMgmtList', val={'V':b'\0'}, IE=BridgeMgmtList())
        )


#------------------------------------------------------------------------------#
# Manage Bridge complete
# TS 24.519, section 8.8
#------------------------------------------------------------------------------#

class ManageBridgeComplete(Layer3E):
    _GEN = (
        Uint8('Type', val=2, dic=TSNAFBridgeMsgType_dict),
        Type6TLVE('BridgeMgmtCap', val={'T':0x70, 'V':b'\0\0'}, IE=BridgeMgmtCap()),
        Type6TLVE('BridgeStat', val={'T':0x71, 'V':b'\0\0'}, IE=BridgeStat()),
        Type6TLVE('BridgeUpdRes', val={'T':0x72, 'V':b'\0\0'}, IE=BridgeUpdRes())
        )


#------------------------------------------------------------------------------#
# Bridge management notify
# TS 24.519, section 8.9
#------------------------------------------------------------------------------#

class BridgeMgmtNotif(Layer3E):
    _GEN = (
        Uint8('Type', val=3, dic=TSNAFBridgeMsgType_dict),
        Type6LVE('BridgeStat', val={'V':b'\0\0'}, IE=BridgeStat())
        )


#------------------------------------------------------------------------------#
# Bridge management notify ack
# TS 24.519, section 8.10
#------------------------------------------------------------------------------#

class BridgeMgmtNotifAck(Layer3E):
    _GEN = (
        Uint8('Type', val=4, dic=TSNAFBridgeMsgType_dict),
        )


#------------------------------------------------------------------------------#
# 5G TSN-AF Bridge Management dispatcher
#------------------------------------------------------------------------------#

FGTSNAFBridgeTypeClasses = {
    1 : ManageBridgeCommand,
    2 : ManageBridgeComplete,
    3 : BridgeMgmtNotif,
    4 : BridgeMgmtNotifAck
    }

def get_5gtsnaf_bridge_msg_instances():
    return {k: FGTSNAFBridgeTypeClasses[k]() for k in FGTSNAFBridgeTypeClasses}

