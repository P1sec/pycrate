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
# * File Name : pycrate_mobile/ISUP.py
# * Created : 2020-10-23
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from binascii import unhexlify

from pycrate_core.utils  import *
from pycrate_core.repr   import *
from pycrate_core.elt    import *
from pycrate_core.base   import *
from pycrate_core.charpy import *

from .SCCP import (
    Ptr8, Ptr16,
    SCCPBufBCD as ISUPBufBCD,
    SCCPOpt as ISUPOpt,
    SCCPMessage as ISUPMessage
    )


#------------------------------------------------------------------------------#
# ITU-T Q.763: ISDN user part formats and codes
# ISUP
#------------------------------------------------------------------------------#

# classes for providing common methods

class ISUPNum(Envelope):
    """for all ISUP number structures, with Odd/Even indicator and BCD number
    """
    
    def get_num(self):
        """return the BCD-encoded number, properly decoded according to OE
        """
        if self['OE'].get_val():
            return self['Num'].decode()[:-1]
        else:
            return self['Num'].decode()
    
    def set_num(self, num):
        """set the BCD-encoded number and OE
        """
        if len(num) % 2:
            self['OE'].set_val(1)
        self['Num'].encode(num)


class ExtByte(Envelope):
    """Extensible structure for wrapping 7-bit object
    """
    _GEN = (
        Uint('ext', val=1, bl=1),
        Uint('cont', bl=7, rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)


class ExtSeq(Sequence):
    """Extensible sequence for future extension
    if ext == 1, this is the last byte, otherwise 1 more byte
    """
    _GEN = ExtByte()
    
    def _from_char(self, char):
        if self.get_trans():
            return
        #
        # init content
        self._content = []
        #
        # consume 1st byte
        byte = self._tmpl.clone()
        byte._env = self
        byte._from_char(char)
        self._content.append(byte)
        #
        # consume more bytes
        while byte['ext'].get_val() == 0:
            byte = self._tmpl.clone()
            byte._env = self
            byte._from_char(char)
            self._content.append(byte)


def make_ext(Obj, ext=None):
    """Wraps a 7-bit object Obj into an extensible object ExtByte
    """
    if ext in (0, 1):
        # overwrite next value automation
        ext = ExtByte(val={'ext': ext})
    else:
        ext = ExtByte()
    ext.replace(ext['cont'], Obj)
    return ext


#------------------------------------------------------------------------------#
# ISUP message type
# ITU-T Q.763, section 1.3
#------------------------------------------------------------------------------#

ISUPType_dict = {
    0x06 : 'Address complete',
    0x09 : 'Answer',
    0x41 : 'Application transport',
    0x13 : 'Blocking',
    0x15 : 'Blocking acknowledgement',
    0x2c : 'Call progress',
    0x18 : 'Circuit group blocking',
    0x1a : 'Circuit group blocking acknowledgement',
    0x2a : 'Circuit group query (national use)',
    0x2b : 'Circuit group query response (national use)',
    0x17 : 'Circuit group reset',
    0x29 : 'Circuit group reset acknowledgement',
    0x19 : 'Circuit group unblocking',
    0x1b : 'Circuit group unblocking acknowledgement',
    0x31 : 'Charge information (national use)',
    0x2f : 'Confusion',
    0x07 : 'Connect',
    0x05 : 'Continuity',
    0x11 : 'Continuity check request',
    0x33 : 'Facility',
    0x20 : 'Facility accepted',
    0x21 : 'Facility reject',
    0x1f : 'Facility request',
    0x8  : 'Forward transfer',
    0x36 : 'Identification request',
    0x37 : 'Identification response',
    0x4  : 'Information (national use)',
    0x3  : 'Information request (national use)',
    0x1  : 'Initial address',
    0x24 : 'Loop back acknowledgement (national use)',
    0x40 : 'Loop prevention',
    0x32 : 'Network resource management',
    0x30 : 'Overload (national use)',
    0x28 : 'Pass-along (national use)',
    0x42 : 'Pre-release information',
    0xc  : 'Release',
    0x10 : 'Release complete',
    0x12 : 'Reset circuit',
    0xe  : 'Resume',
    0x38 : 'Segmentation',
    0x2  : 'Subsequent address',
    0x43 : 'Subsequent Directory Number (national use)',
    0xd  : 'Suspend',
    0x14 : 'Unblocking',
    0x16 : 'Unblocking acknowledgement',
    0x2e : 'Unequipped CIC (national use)',
    0x35 : 'User Part available',
    0x34 : 'User Part test',
    0x2d : 'User-to-user information'
    }


#------------------------------------------------------------------------------#
# ISUP parameter names
# ITU-T Q.763, section 3.1
#------------------------------------------------------------------------------#

ISUPParam_dict = {
    0x2e : 'Access delivery information',
    0x3  : 'Access transport',
    0x78 : 'Application transport',
    0x27 : 'Automatic congestion level',
    0x11 : 'Backward call indicators',
    0x4d : 'Backward GVNS',
    0x36 : 'Call diversion information',
    0x6e : 'Call diversion treatment indicators',
    0x2d : 'Call history information',
    0x70 : 'Call offering treatment indicators',
    0x1  : 'Call reference (national use)',
    0x45 : 'Call transfer number',
    0x43 : 'Call transfer reference',
    0x6f : 'Called IN number',
    0x7d : 'Called directory number (national use)',
    0x4  : 'Called party number',
    0x81 : 'Calling geodetic location',
    0xa  : 'Calling party number',
    0x9  : 'Calling party\'s category',
    0x12 : 'Cause indicators',
    0x7a : 'CCNR possible indicator',
    0x4b : 'CCSS',
    0x71 : 'Charged party identification (national use)',
    0x25 : 'Circuit assignment map',
    0x15 : 'Circuit group supervision message type',
    0x26 : 'Circuit state indicator (national use)',
    0x1a : 'Closed user group interlock code',
    0x79 : 'Collect call request',
    0x72 : 'Conference treatment indicators',
    0x21 : 'Connected number',
    0xd  : 'Connection request',
    0x10 : 'Continuity indicators',
    0x65 : 'Correlation id',
    0x73 : 'Display information',
    0x37 : 'Echo control information',
    0x0  : 'End of optional parameters',
    0x24 : 'Event information',
    0x18 : 'Facility indicator',
    0x7  : 'Forward call indicators',
    0x4c : 'Forward GVNS',
    0xc1 : 'Generic digits (national use)',
    0x2c : 'Generic notification indicator',
    0xc0 : 'Generic number',
    0x82 : 'HTR information',
    0x3d : 'Hop counter',
    0xf  : 'Information indicators (national use)',
    0xe  : 'Information request indicators (national use)',
    0x3f : 'Location number',
    0x44 : 'Loop prevention indicators',
    0x3b : 'MCID request indicators',
    0x3c : 'MCID response indicators',
    0x38 : 'Message compatibility information',
    0x3a : 'MLPP precedence',
    0x6  : 'Nature of connection indicators',
    0x5b : 'Network management controls',
    0x84 : 'Network routing number (national use)',
    0x2f : 'Network specific facility (national use)',
    0x8d : 'Number portability forward information (network option)',
    0x29 : 'Optional backward call indicators',
    0x8  : 'Optional forward call indicators',
    0x28 : 'Original called number',
    0x7f : 'Original called IN number',
    0x2b : 'Origination ISC point code',
    0x39 : 'Parameter compatibility information',
    0x7b : 'Pivot capability',
    0x87 : 'Pivot counter',
    0x89 : 'Pivot routing backward information',
    0x88 : 'Pivot routing forward information',
    0x7c : 'Pivot routing indicators',
    0x86 : 'Pivot status (national use)',
    0x31 : 'Propagation delay counter',
    0x85 : 'Query on release capability (network option)',
    0x16 : 'Range and status',
    0x8c : 'Redirect backward information (national use)',
    0x4e : 'Redirect capability (national use)',
    0x77 : 'Redirect counter (national use)',
    0x8b : 'Redirect forward information (national use)',
    0x8a : 'Redirect status (national use)',
    0xb  : 'Redirecting number',
    0x13 : 'Redirection information',
    0xc  : 'Redirection number',
    0x40 : 'Redirection number restriction',
    0x32 : 'Remote operations (national use)',
    0x66 : 'SCF id',
    0x33 : 'Service activation',
    0x1e : 'Signalling point code (national use)',
    0x5  : 'Subsequent number',
    0x22 : 'Suspend/Resume indicators',
    0x23 : 'Transit network selection (national use)',
    0x2  : 'Transmission medium requirement',
    0x3e : 'Transmission medium requirement prime',
    0x35 : 'Transmission medium used',
    0x74 : 'UID action indicators',
    0x75 : 'UID capability indicators',
    0x1d : 'User service information',
    0x30 : 'User service information prime',
    0x34 : 'User teleservice information',
    0x2a : 'User-to-user indicators',
    0x20 : 'User-to-user information'
    }


def Variable(param):
    """prefix the parameter element `param' with an uint8 as len
    """
    class Variable(Envelope):
        _GEN = (
            Uint8('Len'),
            param
            )
        def __init__(self, *args, **kwargs):
            Envelope.__init__(self, *args, **kwargs)
            self[0].set_valauto(lambda: self[1].get_len())
            self[1].set_blauto(lambda: self[0].get_val()<<3)
    w = Variable(param._name)
    return w


def Optional(param, name):
    """prefix the parameter element `param' with an uint8 as name and an uint8 
    as len, and make it transparent by default
    """
    if param._name == 'EOO':
        w = Envelope(param._name, GEN=(param, ), trans=True)
    else:
        # wrap with name and length prefix
        class Option(Envelope):
            _GEN = (
                Uint8('Name', val=name, dic=ISUPParam_dict),
                Uint8('Len'),
                param
                )
            def __init__(self, *args, **kwargs):
                Envelope.__init__(self, *args, **kwargs)
                self[1].set_valauto(lambda: self[2].get_len())
                if not hasattr(param, '_bl') or param._bl is None:
                    self[2].set_blauto(lambda: self[1].get_val()<<3)
                self.set_trans(True)
        w = Option(param._name)
    return w


#------------------------------------------------------------------------------#
# Access delivery information
# ITU-T Q.763, section 3.2
#------------------------------------------------------------------------------#

class AccessDeliveryInfo(Envelope):
    _GEN = (
        Uint('spare', bl=7),
        Uint('Value', bl=1, dic={0:'set-up message generated', 1:'no set-up message generated'})
        )


#------------------------------------------------------------------------------#
# Access transport
# ITU-T Q.763, section 3.3
#------------------------------------------------------------------------------#

_Q931SIEV_ID_dict = {
    0 : 'Reserved',
    1 : 'Shift',
    2 : 'IE ID',
    3 : 'Congestion level',
    5 : 'Repeat indicator'
    }

_Q931SIE_ID_dict = {
    0 : 'More data',
    1 : 'Sending complete'
    }

_Q931MIE_ID_dict = {
    0x0  : 'Segmented message',
    0x4  : 'Bearer capability',
    0x8  : 'Cause',
    0x10 : 'Call identity',
    0x14 : 'Call state',
    0x18 : 'Channel identification',
    0x1e : 'Progress indicator',
    0x20 : 'Network-specific facilities',
    0x27 : 'Notification indicator',
    0x28 : 'Display',
    0x29 : 'Date/time',
    0x2c : 'Keypad facility',
    0x34 : 'Signal',
    0x40 : 'Information rate',
    0x42 : 'End-to-end transit delay',
    0x43 : 'Transit delay selection and indication',
    0x44 : 'Packet layer binary parameters',
    0x45 : 'Packet layer window size',
    0x46 : 'Packet size',
    0x47 : 'Closed user group',
    0x4a : 'Reverse charging indication',
    0x6c : 'Calling party number',
    0x6d : 'Calling party subaddress',
    0x70 : 'Called party number',
    0x71 : 'Called party subaddress',
    0x74 : 'Redirecting number',
    0x78 : 'Transit network selection',
    0x79 : 'Restart indicator',
    0x7c : 'Low layer compatibility',
    0x7d : 'High layer compatibility',
    0x7e : 'User-user',
    0x7f : 'Escape for extension',
    }


class _Q931_SIE(Envelope):
    _GEN = (
        Uint('ID', val=5, bl=3, dic=_Q931SIEV_ID_dict),
        Alt('', GEN={
            0 : Uint('Val', bl=4),
            1 : Uint('Val', bl=4),
            2 : Uint('ID', bl=4, dic=_Q931SIE_ID_dict),
            3 : Uint('Val', bl=4),
            5 : Uint('Val', bl=4)
            },
            DEFAULT=Uint('res', bl=4),
            sel=lambda self: self.get_env()['ID'].get_val())
        )


class _Q931_MIE(Envelope):
    _GEN = (
        Uint('ID', bl=7, dic=_Q931MIE_ID_dict),
        Uint8('Len'),
        Buf('Val', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda: self['Val'].get_len())
        self['Val'].set_blauto(lambda: self['Len'].get_val()<<3)


class Q931IE(Envelope):
    _GEN = (
        Uint('S', dic={0: 'variable length', 1: 'single octet'}),
        Alt('IE', GEN={
            0 : _Q931_MIE('MIE'),
            1 : _Q931_SIE('SIE')
            })
        )


class AccessTransport(Sequence):
    _GEN = Q931IE()


#------------------------------------------------------------------------------#
# Automatic congestion level
# ITU-T Q.763, section 3.4
#------------------------------------------------------------------------------#

class AutomaticCongestionLevel(Uint8):
    dic = {
        1 : 'congestion level 1 exceeded',
        2 : 'congestion level 2 exceeded'
        }


#------------------------------------------------------------------------------#
# Backward call indicators
# ITU-T Q.763, section 3.5
#------------------------------------------------------------------------------#

_EtoEMethodInd_dict = {
    0 : 'no end-to-end method available (only link-by-link method available)',
    1 : 'pass-along method available (national use)',
    2 : 'SCCP method available',
    3 : 'pass-along and SCCP methods available (national use)'
    }

_CalledPartyCatInd_dict = {
    0 : 'no indication',
    1 : 'ordinary subscriber',
    2 : 'payphone',
    3 : 'spare'
    }

_CalledPartyStatusInd_dict = {
    0 : 'no indication',
    1 : 'subscriber free',
    2 : 'connect when free (national use)',
    3 : 'spare'
    }

_ChargeInd_dict = {
    0 : 'no indication',
    1 : 'no charge',
    2 : 'charge',
    3 : 'spare'
    }

_SCCPMethodInd_dict = {
    0 : 'no indication',
    1 : 'connectionless method available (national use)',
    2 : 'connection oriented method available',
    3 : 'connectionless and connection oriented methods available (national use)'
    }

_EchoControlDeviceInd_dict = {
    0 : 'incoming echo control device not included',
    1 : 'incoming echo control device included'
    }

_ISDNAccessInd_dict = {
    0 : 'terminating access non-ISDN',
    1 : 'terminating access ISDN'
    }

_HoldingInd_dict = {
    0 : 'holding not requested',
    1 : 'holding requested'
    }

_ISDNUserPartInd_dict = {
    0 : 'ISDN user part not used all the way',
    1 : 'ISDN user part used all the way'
    }

_EtoEInfoInd_dict = {
    0 : 'no end-to-end information available',
    1 : 'end-to-end information available'
    }

_InterworkingInd_dict = {
    0 : 'no interworking encountered (Signalling System No. 7 all the way)',
    1 : 'interworking encountered'
    }


class BackwardCallInd(Envelope):
    _GEN = (
        Uint('EtoEMethodInd', bl=2, dic=_EtoEMethodInd_dict),
        Uint('CalledPartyCatInd', bl=2, dic=_CalledPartyCatInd_dict),
        Uint('CalledPartyStatusInd', bl=2, dic=_CalledPartyStatusInd_dict),
        Uint('ChargeInd', bl=2, dic=_ChargeInd_dict),
        Uint('SCCPMethodInd', bl=2, dic=_SCCPMethodInd_dict),
        Uint('EchoControlDeviceInd', bl=1, dic=_EchoControlDeviceInd_dict),
        Uint('ISDNAccessInd', bl=1, dic=_ISDNAccessInd_dict),
        Uint('HoldingInd', bl=1, dic=_HoldingInd_dict),
        Uint('ISDNUserPartInd', bl=1, dic=_ISDNUserPartInd_dict),
        Uint('EtoEInfoInd', bl=1, dic=_EtoEInfoInd_dict),
        Uint('InterworkingInd', bl=1, dic=_InterworkingInd_dict)
        )


#------------------------------------------------------------------------------#
# Call diversion information
# ITU-T Q.763, section 3.6
#------------------------------------------------------------------------------#

_RedirectingReason_dict = {
    0 : 'Unknown',
    1 : 'User busy',
    2 : 'no reply',
    3 : 'unconditional',
    4 : 'deflection during alerting',
    5 : 'deflection immediate response',
    6 : 'mobile subscriber not reachable'
    }

_NotifSubsOptions_dict = {
    0 : 'Unknown',
    1 : 'presentation not allowed',
    2 : 'presentation allowed with redirection number',
    3 : 'presentation allowed without redirection number'
    }


class CallDiversionInfo(Envelope):
    _GEN = (
        Uint('spare', bl=1),
        Uint('RedirectingReason', bl=4, dic=_RedirectingReason_dict),
        Uint('NotifSubsOptions', bl=3, dic=_NotifSubsOptions_dict)
        )


#------------------------------------------------------------------------------#
# Call diversion information
# ITU-T Q.763, section 3.7
#------------------------------------------------------------------------------#

class CallHistoryInfo(Uint16):
    pass


#------------------------------------------------------------------------------#
# Call reference (national use)
# ITU-T Q.763, section 3.8
#------------------------------------------------------------------------------#

class CallReference(Envelope):
    _GEN = (
        Uint24('CallIdentity'),
        Uint16LE('SignallingPointCode')
        )


#------------------------------------------------------------------------------#
# Called party number
# ITU-T Q.763, section 3.9
#------------------------------------------------------------------------------#

_NumOE_dict = {
    0 : 'even number of address signals',
    1 : 'odd number of address signals'
    }

_NumNAI_dict = {
    0 : 'spare',
    1 : 'subscriber number (national use)',
    2 : 'unknown (national use)',
    3 : 'national (significant) number',
    4 : 'international number',
    5 : 'network-specific number (national use)',
    6 : 'network routing number in national (significant) number format (national use)',
    7 : 'network routing number in network-specific number format (national use)',
    8 : 'network routing number concatenated with Called Directory Number (national use)'
    }

for i in range(112, 126):
    _NumNAI_dict[i] = 'reserved for national use'

_NumINN_dict = {
    0 : 'routing to internal network number allowed',
    1 : 'routing to internal network number not allowed'
    }

_NumPlan_dict = {
    0 : 'spare',
    1 : 'ISDN (Telephony) numbering plan (ITU-T Recommendation E.164)',
    2 : 'spare',
    3 : 'Data numbering plan (ITU-T Recommendation X.121) (national use)',
    4 : 'Telex numbering plan (ITU-T Recommendation F.69) (national use)',
    5 : 'private numbering plan (national use)',
    6 : 'reserved for national use',
    7 : 'spare'
    }


class CalledPartyNum(ISUPNum):
    _GEN = (
        Uint('OE', bl=1, dic=_NumOE_dict),
        Uint('NAI', val=1, bl=7, dic=_NumNAI_dict),
        Uint('INN', bl=1, dic=_NumINN_dict),
        Uint('NumPlan', bl=3, dic=_NumPlan_dict),
        Uint('spare', bl=4, rep=REPR_HEX),
        ISUPBufBCD('Num', val=b'')
        )


#------------------------------------------------------------------------------#
# Calling party number
# ITU-T Q.763, section 3.10
#------------------------------------------------------------------------------#

_NINum_dict = {
    0 : 'number complete',
    1 : 'number incomplete'
    }

_AddrPresInd_dict = {
    0 : 'presentation allowed',
    1 : 'presentation restricted',
    2 : 'address not available (national use)',
    3 : 'reserved for restriction by the network'
    }

_ScreeningInd_dict = {
    0 : 'reserved',
    1 : 'user provided, verified and passed',
    2 : 'reserved',
    3 : 'network provided'
    }


class CallingPartyNum(ISUPNum):
    _GEN = (
        Uint('OE', bl=1, dic=_NumOE_dict),
        Uint('NAI', val=1, bl=7, dic=_NumNAI_dict),
        Uint('NI', bl=1, dic=_NINum_dict),
        Uint('NumPlan', bl=3, dic=_NumPlan_dict),
        Uint('AddrPresInd', bl=2, dic=_AddrPresInd_dict),
        Uint('ScreeningInd', bl=2, dic=_ScreeningInd_dict),
        ISUPBufBCD('Num', val=b'')
        )


#------------------------------------------------------------------------------#
# Calling party's category
# ITU-T Q.763, section 3.11
#------------------------------------------------------------------------------#

_CallingPartyCat_dict = {
    0 : 'calling party\'s category unknown at this time (national use)',
    1 : 'operator, language French',
    2 : 'operator, language English',
    3 : 'operator, language German',
    4 : 'operator, language Russian',
    5 : 'operator, language Spanish',
    9 : 'reserved',
    10 : 'ordinary calling subscriber',
    11 : 'calling subscriber with priority',
    12 : 'data call (voice band data)',
    13 : 'test call',
    14 : 'spare',
    15 : 'payphone',
    }

for i in range(224, 255):
    _CallingPartyCat_dict[i] = 'reserved for national use'


class CallingPartyCat(Uint8):
    _dic = _CallingPartyCat_dict


#------------------------------------------------------------------------------#
# Cause indicator
# ITU-T Q.763, section 3.12
#------------------------------------------------------------------------------#

_CodingStd_dict = {
    0 : 'ITU-T standardized coding',
    1 : 'ISO/IEC standard',
    2 : 'national standard',
    3 : 'standard specific to identified location'
    }

_Location_dict = {
    0 : 'user (U)',
    1 : 'private network serving the local user (LPN)',
    2 : 'public network serving the local user (LN)',
    3 : 'transit network (TN)',
    4 : 'public network serving the remote user (RLN)',
    5 : 'private network serving the remote user (RPN)',
    7 : 'international network (INTL)',
    10 : 'network beyond interworking point (BI)',
    12 : 'reserved for national use',
    13 : 'reserved for national use',
    14 : 'reserved for national use',
    15 : 'reserved for national use',
    }

_CauseClass_dict = {
    1 : 'normal event',
    2 : 'resource unavailable',
    3 : 'service or option not available',
    4 : 'service or option not implemented',
    5 : 'invalid message',
    6 : 'protocol error',
    7 : 'interworking'
    }

_CauseValue_dict = {
    0 : {
        1 : 'Unallocated (unassigned) number',
        2 : 'No route to specified transit network',
        3 : 'No route to destination',
        4 : 'Send special information tone',
        5 : 'Misdialled trunk prefix',
        6 : 'Channel unacceptable',
        7 : 'Call awarded and being delivered in an established channel',
        8 : 'Pre-emption',
        9 : 'Pre-emption – circuit reserved for reuse',
        13 : 'Call completed elsewhere'
        },
    1 : {
        0 : 'Normal call clearing',
        1 : 'User busy',
        2 : 'No user responding',
        3 : 'No answer from user (user alerted)',
        4 : 'Subscriber absent',
        5 : 'Call rejected',
        6 : 'Number changed',
        7 : 'Redirection to new destination',
        9 : 'Exchange routing error',
        10 : 'Non-selected user clearing',
        11 : 'Destination out of order',
        12 : 'Invalid number format (address incomplete)',
        13 : 'Facility rejected',
        14 : 'Response to STATUS ENQUIRY',
        15 : 'Normal, unspecified',
        },
    2 : {
        2 : 'No circuit/channel available',
        6 : 'Network out of order',
        7 : 'Permanent frame mode connection out of service',
        8 : 'Permanent frame mode connection operational',
        9 : 'Temporary failure',
        10 : 'Switching equipment congestion',
        11 : 'Access information discarded',
        12 : 'Requested circuit/channel not available',
        14 : 'Precedence call blocked',
        15 : 'Resource unavailable, unspecified'
        },
    3 : {
        1 : 'Quality of service not available',
        2 : 'Requested facility not subscribed',
        5 : 'Outgoing calls barred within CUG',
        7 : 'Incoming calls barred within CUG',
        9 : 'Bearer capability not authorized',
        10 : 'Bearer capability not presently available',
        14 : 'Inconsistency in designated outgoing access information and subscriber class',
        15 : 'Service or option not available, unspecified'
        },
    4 : {
        1 : 'Bearer capability not implemented',
        2 : 'Channel type not implemented',
        5 : 'Requested facility not implemented',
        6 : 'Only restricted digital information bearer capability is available',
        15 : 'Service or option not implemented, unspecified'
        },
    5 : {
        1 : 'Invalid call reference value',
        2 : 'Identified channel does not exist',
        3 : 'A suspended call exists, but this call identity does not',
        4 : 'Call identity in use',
        5 : 'No call suspended',
        6 : 'Call with the requested call identity has been cleared',
        7 : 'User not member of CUG',
        8 : 'Incompatible destination',
        10 : 'Non-existent CUG',
        11 : 'Invalid transit network selection',
        15 : 'Invalid message, unspecified',
        },
    6 : {
        0 : 'Mandatory information element is missing',
        1 : 'Message type non-existent or not implemented',
        2 : 'Message not compatible with call state or Message type message type non-existent or not implemented',
        3 : 'Information element /parameter non-existent or not implemented',
        4 : 'Invalid information element contents',
        5 : 'Message not compatible with call state',
        6 : 'Recovery on timer expiry',
        7 : 'Parameter non-existent or not implemented, passed on',
        14 : 'Message with unrecognized parameter, discarded',
        15 : 'Protocol error, unspecified',
        },
    7 : {
        15 : 'Interworking, unspecified'
        }
    }


class CauseInd(Envelope):
    _GEN = (
        Uint('ext', val=0, bl=1),
        Uint('CodingStd', bl=2, dic=_CodingStd_dict),
        Uint('spare', bl=1),
        Uint('Location', bl=4, dic=_Location_dict),
        Uint('ext', val=1, bl=1),
        Uint('Class', bl=3, dic=_CauseClass_dict),
        Uint('Cause', bl=4),
        Buf('Diagnostic', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Cause'].set_dicauto(lambda: _CauseValue_dict.get(self['Class'].get_val(), {}))
        self['Diagnostic'].set_transauto(lambda: True if self[4].get_val() else False)


#------------------------------------------------------------------------------#
# Circuit group supervision message type
# ITU-T Q.763, section 3.13
#------------------------------------------------------------------------------#

_CircuitGroupSupervis_dict = {
    0 : 'maintenance oriented',
    1 : 'hardware failure oriented',
    2 : 'reserved for national use (used in 1984 version)',
    3 : 'spare'
    }

class CircuitGroupSupervis(Envelope):
    _GEN = (
        Uint('spare', bl=6),
        Uint('Value', bl=2, dic=_CircuitGroupSupervis_dict)
        )


#------------------------------------------------------------------------------#
# Circuit state indicator (national use)
# ITU-T Q.763, section 3.14
#------------------------------------------------------------------------------#

_HardwareBlockingState_dict = {
    0 : 'no blocking (active)',
    1 : 'locally blocked',
    2 : 'remotely blocked',
    3 : 'locally and remotely blocked'
    }

_CallProcessingState_dict = {
    1 : 'circuit incoming busy',
    2 : 'circuit outgoing busy',
    3 : 'idle'
    }

_MaintenanceBlockingState_dict = {
    0 : 'no blocking (active)',
    1 : 'locally blocked',
    2 : 'remotely blocked',
    3 : 'locally and remotely blocked'
    }

_MaintenanceBlockingState_nocall_dict = {
    0 : 'transient',
    1 : 'spare',
    2 : 'spare',
    3 : 'unequipped'
    }


class _CSInd(Envelope):
    _GEN = (
        Uint('spare', bl=2),
        Uint('HardwareBlockingState', bl=2, dic=_HardwareBlockingState_dict), 
        Uint('CallProcessingState', bl=2, dic=_CallProcessingState_dict),
        Uint('MaintenanceBlockingState', bl=2)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['MaintenanceBlockingState'].set_dicauto(
            lambda: _MaintenanceBlockingState_nocall_dict if self['CallProcessingState'].get_val() == 0 \
                    else _MaintenanceBlockingState_dict)


class CircuitStateInd(Array):
    _GEN = _CSInd('CSInd')


#------------------------------------------------------------------------------#
# Closed user group interlock code
# ITU-T Q.763, section 3.15
#------------------------------------------------------------------------------#

class ClosedUserGroupInterlockCode(Envelope):
    _GEN = (
        Uint16('NetworkIdent', rep=REPR_HEX),
        Uint16('Code', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Connected number
# ITU-T Q.763, section 3.16
#------------------------------------------------------------------------------#

class ConnectedNum(ISUPNum):
    _GEN = (
        Uint('OE', bl=1, dic=_NumOE_dict),
        Uint('NAI', val=1, bl=7, dic=_NumNAI_dict),
        Uint('spare', bl=1),
        Uint('NumPlan', bl=3, dic=_NumPlan_dict),
        Uint('AddrPresInd', bl=2, dic=_AddrPresInd_dict),
        Uint('ScreeningInd', bl=2, dic=_ScreeningInd_dict),
        ISUPBufBCD('Num', val=b'')
        )


#------------------------------------------------------------------------------#
# Connection request
# ITU-T Q.763, section 3.17
#------------------------------------------------------------------------------#

class ConnectionReq(Envelope):
    _GEN = (
        Uint24('LocalRef'),
        Uint16LE('SignallingPointCode'),
        Uint8('ProtocolClass'),
        Uint8('Credit')
        )


#------------------------------------------------------------------------------#
# Continuity indicator
# ITU-T Q.763, section 3.18
#------------------------------------------------------------------------------#

_ContinuityInd_dict = {
    0 : 'continuity check failed',
    1 : 'continuity check successful'
    }


class ContinuityInd(Envelope):
    _GEN = (
        Uint('spare', bl=7),
        Uint('Value', bl=1, dic=_ContinuityInd_dict)
        )


#------------------------------------------------------------------------------#
# Echo control information
# ITU-T Q.763, section 3.19
#------------------------------------------------------------------------------#

_IncomingEchoControlDeviceReqInd_dict = {
    0 : 'no information',
    1 : 'incoming echo control device activation request',
    2 : 'incoming echo control device deactivation request',
    3 : 'spare'
    }

_OutgoingEchoControlDeviceReqInd_dict = {
    0 : 'no information',
    1 : 'outgoing echo control device activation request',
    2 : 'outgoing echo control device deactivation request',
    3 : 'spare'
    }

_IncomingEchoControlDeviceInfoInd_dict = {
    0 : 'no information',
    1 : 'incoming echo control device not included and not available',
    2 : 'incoming echo control device included',
    3 : 'incoming echo control device not included but available'
    }

_OutgoingEchoControlDeviceInfoInd_dict = {
    0 : 'no information',
    1 : 'outgoing echo control device not included and not available',
    2 : 'outgoing echo control device included',
    3 : 'outgoing echo control device not included but available'
    }


class EchoControlInfo(Envelope):
    _GEN = (
        Uint('IncomingEchoControlDeviceReqInd', bl=2, dic=_IncomingEchoControlDeviceReqInd_dict),
        Uint('OutgoingEchoControlDeviceReqInd', bl=2, dic=_OutgoingEchoControlDeviceReqInd_dict),
        Uint('IncomingEchoControlDeviceInfoInd', bl=2, dic=_IncomingEchoControlDeviceInfoInd_dict),
        Uint('OutgoingEchoControlDeviceInfoInd', bl=2, dic=_OutgoingEchoControlDeviceInfoInd_dict)
        )


#------------------------------------------------------------------------------#
# End of optional parameters
# ITU-T Q.763, section 3.20
#------------------------------------------------------------------------------#

class EOO(Uint8):
    _val = 0
    _dic = ISUPParam_dict


#------------------------------------------------------------------------------#
# Event information
# ITU-T Q.763, section 3.21
#------------------------------------------------------------------------------#

_EventInd_dict = {
    0 : 'spare',
    1 : 'ALERTING',
    2 : 'PROGRESS',
    3 : 'in-band information or an appropriate pattern is now available',
    4 : 'call forwarded on busy (national use)',
    5 : 'call forwarded on no reply (national use)',
    6 : 'call forwarded unconditional (national use)'
    }


class EventInfo(Envelope):
    _GEN = (
        Uint('EventPresInd', bl=1, dic={0: 'no indication', 1: 'presentation restricted'}),
        Uint('EventInd', bl=7, dic=_EventInd_dict)
        )


#------------------------------------------------------------------------------#
# Facility indicator
# ITU-T Q.763, section 3.22
#------------------------------------------------------------------------------#

class FacilityInd(Uint8):
    _dic = {
        2 : 'user-to-user service'
        }


#------------------------------------------------------------------------------#
# Forward call indicators
# ITU-T Q.763, section 3.23
#------------------------------------------------------------------------------#

_ISDNUserPartPrefInd_dict = {
    0 : 'ISDN user part preferred all the way',
    1 : 'ISDN user part not required all the way',
    2 : 'ISDN user part required all the way',
    3 : 'spare'
    }

_InternatCallInd_dict = {
    0 : 'call to be treated as a national call',
    1 : 'call to be treated as an international call'
    }

_ISDNAccessInd2_dict = {
    0 : 'originating access non-ISDN',
    1 : 'originating access ISDN',
    }


class ForwardCallInd(Envelope):
    _GEN = (
        Uint('ISDNUserPartPrefInd', bl=2, dic=_ISDNUserPartPrefInd_dict),
        Uint('ISDNUserPartInd', bl=1, dic=_ISDNUserPartInd_dict),
        Uint('EtoEInfoInd', bl=1, dic=_EtoEInfoInd_dict),
        Uint('InterworkingInd', bl=1, dic=_InterworkingInd_dict),
        Uint('EtoEMethodInd', bl=2, dic=_EtoEMethodInd_dict),
        Uint('InternatCallInd', bl=1, dic=_InternatCallInd_dict),
        Uint('ReservedNationalUse', bl=4),
        Uint('spare', bl=1),
        Uint('SCCPMethodInd', bl=2, dic=_SCCPMethodInd_dict),
        Uint('ISDNAccessInd', bl=1, dic=_ISDNAccessInd2_dict)
        )


#------------------------------------------------------------------------------#
# Generic digits (national use)
# ITU-T Q.763, section 3.24
#------------------------------------------------------------------------------#

_DigitsEncoding_dict = {
    0 : 'BCD even',
    1 : 'BCD odd',
    2 : 'IA5 character',
    3 : 'binary coded'
    }

_DigitsType_dict = {
    0 : 'reserved for account code',
    1 : 'reserved for authorisation code',
    2 : 'reserved for private networking travelling class mark',
    3 : 'reserved for business communication group identity'
    }

for i in range(4, 31):
    _DigitsType_dict[i] = 'reserved for national use'


class GenericDigits(Envelope):
    _GEN = (
        Uint('Encoding', bl=3, dic=_DigitsEncoding_dict),
        Uint('Type', bl=5, dic=_DigitsType_dict),
        Buf('Digits', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Generic notification indicator
# ITU-T Q.763, section 3.25
#------------------------------------------------------------------------------#

_GenericNotifInd_dict = {
    0 : 'user suspended',
    1 : 'user resumed',
    2 : 'bearer service change',
    3 : 'discriminator for extension to ASN.1 encoded component (used in DSS1)',
    4 : 'call completion delay',
    0x42 : 'conference established',
    0x43 : 'conference disconnected',
    0x44 : 'other party added',
    0x45 : 'isolated',
    0x46 : 'reattached',
    0x47 : 'other party isolated',
    0x48 : 'other party reattached',
    0x49 : 'other party split',
    0x40 : 'other party disconnected',
    0x41 : 'conference floating',
    0x60 : 'call is a waiting call',
    0x68 : 'diversion activated (used in DSS1)',
    0x69 : 'call transfer, alerting',
    0x70 : 'call transfer, active',
    0x79 : 'remote hold',
    0x7a : 'remote retrieval',
    0x7b : 'call is diverting'
    }


class GenericNotifInd(Envelope):
    _GEN = (
        Uint('ext', val=1, bl=1),
        Uint('Value', bl=7, dic=_GenericNotifInd_dict)
        )


#------------------------------------------------------------------------------#
# Generic number
# ITU-T Q.763, section 3.26
#------------------------------------------------------------------------------#

_NumQualifInd_dict = {
    0 : 'reserved (dialled digits) (national use)',
    1 : 'additional called number (national use)',
    2 : 'reserved (supplemental user provided calling number – failed network screening) (national use)',
    3 : 'reserved (supplemental user provided calling number – not screened) (national use)',
    4 : 'reserved (redirecting terminating number) (national use)',
    5 : 'additional connected number',
    6 : 'additional calling party number',
    7 : 'reserved for additional original called number',
    8 : 'reserved for additional redirecting number',
    9 : 'reserved for additional redirection number',
    10 : 'reserved (used in 1992 version)',
    255 : 'reserved for expansion'
    }

for i in range(128, 255):
    _NumQualifInd_dict[i] = 'reserved for national use'

_ScreeningInd2_dict = {
    0 : 'user provided, not verified',
    1 : 'user provided, verified and passed',
    2 : 'user provided, verified and failed',
    3 : 'network provided'
    }

class GenericNum(ISUPNum):
    _GEN = (
        Uint8('NumQualifInd', dic=_NumQualifInd_dict),
        Uint('OE', bl=1, dic=_NumOE_dict),
        Uint('NAI', val=1, bl=7, dic=_NumNAI_dict),
        Uint('spare', bl=1),
        Uint('NumPlan', bl=3, dic=_NumPlan_dict),
        Uint('AddrPresInd', bl=2, dic=_AddrPresInd_dict),
        Uint('ScreeningInd', bl=2, dic=_ScreeningInd2_dict),
        ISUPBufBCD('Num', val=b'')
        )


#------------------------------------------------------------------------------#
# Information indicators (national use)
# ITU-T Q.763, section 3.28
#------------------------------------------------------------------------------#

_SolicitedInfoInd_dict = {
    0 : 'solicited',
    1 : 'unsolicited'
    }

_ChargeInfoRespInd_dict = {
    0 : 'charge information not included',
    1 : 'charge information included'
    }

_CallingPartyCatRespInd_dict = {
    0 : 'calling party\'s category not included',
    1 : 'calling party\'s category included'
    }

_HoldingProvidedInd_dict = {
    0 : 'holding not provided',
    1 : 'holding provided'
    }

_CallingPartyAddrRespInd_dict = {
    0 : 'calling party address not included',
    1 : 'calling party address not available',
    2 : 'spare',
    3 : 'calling party address included'
    }


class InformationInd(Envelope):
    _GEN = (
        Uint('SolicitedInfoInd', bl=1, dic=_SolicitedInfoInd_dict),
        Uint('ChargeInfoRespInd', bl=1, dic=_ChargeInfoRespInd_dict),
        Uint('CallingPartyCatRespInd', bl=1, dic=_CallingPartyCatRespInd_dict),
        Uint('spare', bl=2),
        Uint('HoldingProvidedInd', bl=1, dic=_HoldingProvidedInd_dict),
        Uint('CallingPartyAddrRespInd', bl=1, dic=_CallingPartyAddrRespInd_dict),
        Uint('res', bl=4, rep=REPR_HEX),
        Uint('spare', bl=4, rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Information request indicators (national use)
# ITU-T Q.763, section 3.29
#------------------------------------------------------------------------------#

_MaliciousCallIdReqInd_dict = {
    0 : 'malicious call identification not requested', 
    1 : 'malicious call identification requested'
    }

_ChargeInfoReqInd_dict = {
    0 : 'charge information not requested',
    1 : 'charge information requested'
    }

_CallingPartyCatReqInd_dict = {
    0 : 'calling party\'s category not requested',
    1 : 'calling party\'s category requested'
    }

_CallingPartyAddrReqInd_dict = {
    0 : 'calling party address not requested',
    1 : 'calling party address requested'
    }


class InformationReqInd(Envelope):
    _GEN = (
        Uint('MaliciousCallIdReqInd', bl=1, dic=_MaliciousCallIdReqInd_dict),
        Uint('spare', bl=2),
        Uint('ChargeInfoReqInd', bl=1, dic=_ChargeInfoReqInd_dict),
        Uint('CallingPartyCatReqInd', bl=1, dic=_CallingPartyCatReqInd_dict),
        Uint('spare', bl=1),
        Uint('HoldingInd', bl=1, dic=_HoldingInd_dict),
        Uint('CallingPartyAddrReqInd', bl=1, dic=_CallingPartyAddrReqInd_dict),
        Uint('res', bl=4, rep=REPR_HEX),
        Uint('spare', bl=4, rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Location number
# ITU-T Q.763, section 3.30
#------------------------------------------------------------------------------#

class LocationNum(ISUPNum):
    _GEN = (
        Uint('OE', bl=1, dic=_NumOE_dict),
        Uint('NAI', val=1, bl=7, dic=_NumNAI_dict),
        Uint('INN', bl=1, dic=_NumINN_dict),
        Uint('NumPlan', bl=3, dic=_NumPlan_dict),
        Uint('AddrPresInd', bl=2, dic=_AddrPresInd_dict),
        Uint('ScreeningInd', bl=2, dic=_ScreeningInd_dict),
        ISUPBufBCD('Num', val=b'')
        )


#------------------------------------------------------------------------------#
# MCID request indicators
# ITU-T Q.763, section 3.32
#------------------------------------------------------------------------------#

_MCIDReqInd_dict = {
    0 : 'MCID not requested',
    1 : 'MCID requested'
    }


class MCIDReqInd(Envelope):
    _GEN = (
        Uint('spare', bl=6, rep=REPR_HEX),
        Uint('HoldingProvidedInd', bl=1, dic=_HoldingProvidedInd_dict),
        Uint('MCIDReqInd', bl=1, dic=_MCIDReqInd_dict)
        )


#------------------------------------------------------------------------------#
# MCID response indicators
# ITU-T Q.763, section 3.32
#------------------------------------------------------------------------------#

_MCIDRespInd_dict = {
    0 : 'MCID not included',
    1 : 'MCID included'
    }


class MCIDRespInd(Envelope):
    _GEN = (
        Uint('spare', bl=6, rep=REPR_HEX),
        Uint('HoldingInd', bl=1, dic=_HoldingInd_dict),
        Uint('MCIDRespInd', bl=1, dic=_MCIDRespInd_dict)
        )


#------------------------------------------------------------------------------#
# Message compatibility information
# ITU-T Q.763, section 3.33
#------------------------------------------------------------------------------#

_BroadbandNarrowbandInterworkInd_dict = {
    0 : 'pass on',
    1 : 'discard message',
    2 : 'release call',
    3 : 'reserved, assume 00'
    }

_PassOnNotPossibleInd_dict = {
    0 : 'release call',
    1 : 'discard information'
    }

_DiscardMessageInd_dict = {
    0 : 'do not discard message (pass on)',
    1 : 'discard message'
    }

_SendNotifInd_dict = {
    0 : 'do not send notification',
    1 : 'send notification'    
    }

_ReleaseCallInd_dict = {
    0 : 'do not release call',
    1 : 'release call'
    }

_TransitAtIntermedExchInd_dict = {
    0 : 'transit interpretation',
    1 : 'end node interpretation'
    }


class MessageCompatInfo(Envelope):
    _GEN = (
        Uint('ext', val=1, bl=1),
        Uint('BroadbandNarrowbandInterworkInd', bl=2, dic=_BroadbandNarrowbandInterworkInd_dict),
        Uint('PassOnNotPossibleInd', bl=1, dic=_PassOnNotPossibleInd_dict),
        Uint('DiscardMessageInd', bl=1, dic=_DiscardMessageInd_dict),
        Uint('SendNotifInd', bl=1, dic=_SendNotifInd_dict),
        Uint('ReleaseCallInd', bl=1, dic=_ReleaseCallInd_dict),
        Uint('TransitAtIntermedExchInd', bl=1, dic=_TransitAtIntermedExchInd_dict),
        ExtSeq()
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['ExtSeq'].set_transauto(lambda: True if self['ext'].get_val() else False)


#------------------------------------------------------------------------------#
# MLPP precedence
# ITU-T Q.763, section 3.34
#------------------------------------------------------------------------------#

_LFB_dict = {
    0 : 'Look-ahead For Busy allowed',
    1 : 'path reserved (national use)',
    2 : 'Look-ahead For Busy not allowed',
    3 : 'spare'
    }

_PrecedenceLevel_dict = {
    0 : 'flash override',
    1 : 'flash',
    2 : 'immediate',
    3 : 'priority',
    4 : 'routine'
    }


class MLPPPrecedence(Envelope):
    _GEN = (
        Uint('spare', bl=1),
        Uint('LFB', bl=2, dic=_LFB_dict),
        Uint('spare', bl=1),
        Uint('PrecedenceLevel', bl=4, dic=_PrecedenceLevel_dict),
        Uint16('NetworkIdent', rep=REPR_HEX),
        Uint24('MLPPServiceDom', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Nature of connection indicators
# ITU-T Q.763, section 3.35
#------------------------------------------------------------------------------#

_ContinuityCheckInd_dict = {
    0 : 'continuity check not required',
    1 : 'continuity check required on this circuit',
    2 : 'continuity check performed on a previous circuit',
    3 : 'spare'
    }

_SatelliteInd_dict = {
    0 : 'no satellite circuit in the connection',
    1 : 'one satellite circuit in the connection',
    2 : 'two satellite circuits in the connection',
    3 : 'spare'
    }


class NatureConnectionInd(Envelope):
    _GEN = (
        Uint('spare', bl=3, rep=REPR_HEX),
        Uint('EchoControlDeviceInd', bl=1, dic=_EchoControlDeviceInd_dict),
        Uint('ContinuityCheckInd', bl=2, dic=_ContinuityCheckInd_dict),
        Uint('SatelliteInd', bl=2, dic=_SatelliteInd_dict)
        )


#------------------------------------------------------------------------------#
# Network specific facility (national use)
# ITU-T Q.763, section 3.36
#------------------------------------------------------------------------------#

_TypeOfNetwork_dict = {
    0 : 'CCITT/ITU-T-standardized identification',
    1 : 'spare',
    2 : 'national network identification',
    3 : 'reserved for international network identification (Note)'
    }


class NetworkSpecificFacility(Envelope):
    _GEN = (
        Uint8('Len'),
        Uint('ext', val=1, bl=1),
        Uint('TypeOfNetworkIdent', bl=3, dic=_TypeOfNetwork_dict),
        Uint('NetworkIdentPlan', bl=4),
        ExtSeq('NetworkIdent'),
        Buf('NetworkSpecFacilityInd', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda: 1 + self['NetworkIdent'].get_len())
        self['NetworkIdent'].set_transauto(lambda: True if self['ext'].get_val() else False)
        

#------------------------------------------------------------------------------#
# Optional backward call indicators
# ITU-T Q.763, section 3.37
#------------------------------------------------------------------------------#

_MLPPUserInd_dict = {
    0 : 'no indication',
    1 : 'MLPP user'
    }

_SimpleSegmentationInd_dict = {
    0 : 'no additional information will be sent',
    1 : 'additional information will be sent in a segmentation message'
    }

_CallDiversionMayOccurInd_dict = {
    0 : 'no indication',
    1 : 'call diversion may occur'
    }

_InbandInfoInd_dict = {
    0 : 'no indication',
    1 : 'in-band information or an appropriate pattern is now available'
    }


class OptBackwardCallInd(Envelope):
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('MLPPUsedInd', bl=1, dic=_MLPPUserInd_dict),
        Uint('SimpleSegmentationInd', bl=1, dic=_SimpleSegmentationInd_dict),
        Uint('CallDiversionMayOccurInd', bl=1, dic=_CallDiversionMayOccurInd_dict),
        Uint('InbandInfoInd', bl=1, dic=_InbandInfoInd_dict)
        )


#------------------------------------------------------------------------------#
# Optional forward call indicators
# ITU-T Q.763, section 3.38
#------------------------------------------------------------------------------#

_ConnectedLineIdentReqInd_dict = {
    0 : 'not requested',
    1 : 'requested'
    }

_ClosedUserGroupCallInd_dict = {
    0 : 'non-CUG call',
    1 : 'spare',
    2 : 'closed user group call, outgoing access allowed',
    3 : 'closed user group call, outgoing access not allowed'
    }


class OptForwardCallInd(Envelope):
    _GEN = (
        Uint('ConnectedLineIdentReqInd', bl=1, dic=_ConnectedLineIdentReqInd_dict),
        Uint('spare', bl=4),
        Uint('SimpleSegmentationInd', bl=1, dic=_SimpleSegmentationInd_dict),
        Uint('ClosedUserGroupCallInd', bl=2, dic=_ClosedUserGroupCallInd_dict)
        )


#------------------------------------------------------------------------------#
# Original called number
# ITU-T Q.763, section 3.39
#------------------------------------------------------------------------------#

class OriginalCalledNum(ISUPNum):
    _GEN = (
        Uint('OE', bl=1, dic=_NumOE_dict),
        Uint('NAI', val=1, bl=7, dic=_NumNAI_dict),
        Uint('spare', bl=1),
        Uint('NumPlan', bl=3, dic=_NumPlan_dict),
        Uint('AddrPresInd', bl=2, dic=_AddrPresInd_dict),
        Uint('spare', bl=2),
        ISUPBufBCD('Num', val=b'')
        )


#------------------------------------------------------------------------------#
# Origination ISC point code
# ITU-T Q.763, section 3.40
#------------------------------------------------------------------------------#

class OriginISCPointCode(Uint16LE):
    pass


#------------------------------------------------------------------------------#
# Parameter compatibility information
# ITU-T Q.763, section 3.41
#------------------------------------------------------------------------------#

_PassOnNotPossibleInd2_dict = {
    0 : 'release call',
    1 : 'discard message',
    2 : 'discard parameter',
    3 : 'reserved (interpreted as 00)'
    }

_DiscardParamInd_dict = {
    0 : 'do not discard parameter (pass on)',
    1 : 'discard parameter'
    }


class _ParameterIns0(Envelope):
    _GEN = (
        Uint('PassOnNotPossibleInd', bl=2, dic=_PassOnNotPossibleInd2_dict),
        Uint('DiscardParamInd', bl=1, dic=_DiscardParamInd_dict),
        Uint('DiscardMessageInd', bl=1, dic=_DiscardMessageInd_dict),
        Uint('SendNotifInd', bl=1, dic=_SendNotifInd_dict),
        Uint('ReleaseCallInd', bl=1, dic=_ReleaseCallInd_dict),
        Uint('TransitAtIntermedExchInd', bl=1, dic=_TransitAtIntermedExchInd_dict),
        )


class _ParameterIns1(Envelope):
    _GEN = (
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('BroadbandNarrowbandInterworkInd', bl=2, dic=_BroadbandNarrowbandInterworkInd_dict),
        )


class _ParameterIns(Envelope):
    ENV_SEL_TRANS = False
    _GEN = (
        make_ext(_ParameterIns0('Ins0'), ext=0),
        make_ext(_ParameterIns1('Ins1'), ext=1),
        ExtSeq('MoreIns')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_transauto(lambda: True if self[0].get_val() else False)
        self[2].set_transauto(lambda: True if self[1].get_trans() or self[1].get_val() else False)
    

class _ParameterCompat(Envelope):
    _GEN = (
        Uint8('Param', dic=ISUPParam_dict),
        _ParameterIns('Ins')
        )


class ParameterCompatInfo(Sequence):
    _GEN = _ParameterCompat('ParameterCompat')


#------------------------------------------------------------------------------#
# Propagation delay counter
# ITU-T Q.763, section 3.42
#------------------------------------------------------------------------------#

class PropagationDelayCounter(Uint16):
    pass


#------------------------------------------------------------------------------#
# Range and status
# ITU-T Q.763, section 3.43
#------------------------------------------------------------------------------#

class RangeStatus(Envelope):
    _GEN = (
        Uint8('Range'),
        Buf('Status', val=b'\0', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Redirecting number
# ITU-T Q.763, section 3.44
#------------------------------------------------------------------------------#

class RedirectingNum(OriginalCalledNum):
    pass


#------------------------------------------------------------------------------#
# Redirection information
# ITU-T Q.763, section 3.45
#------------------------------------------------------------------------------#

_OriginalRedirectReason_dict = {
    0 : 'unknown/not available',
    1 : 'user busy (national use)',
    2 : 'no reply (national use)',
    3 : 'unconditional (national use)'
    }

_RedirectingInd_dict = {
    0 : 'no redirection (national use)',
    1 : 'call rerouted (national use)',
    2 : 'call rerouted, all redirection information presentation restricted (national use)',
    3 : 'call diverted',
    4 : 'call diverted, all redirection information presentation restricted',
    5 : 'call rerouted, redirection number presentation restricted (national use)',
    6 : 'call diversion, redirection number presentation restricted (national use)',
    7 : 'spare'
    }

_RedirectingReason_dict = {
    0 : 'unknown/not available',
    1 : 'user busy',
    2 : 'no reply',
    3 : 'unconditional',
    4 : 'deflection during alerting',
    5 : 'deflection immediate response',
    6 : 'mobile subscriber not reachable'
    }


class RedirectionInfo(Envelope):
    _GEN = (
        Uint('OriginalRedirectReason', bl=4, dic=_OriginalRedirectReason_dict),
        Uint('spare', bl=1),
        Uint('RedirectingInd', bl=3, dic=_RedirectingInd_dict),
        Uint('RedirectingReason', bl=4, dic=_RedirectingReason_dict),
        Uint('res', bl=1),
        Uint('RedirectCounter', bl=3)
        )


#------------------------------------------------------------------------------#
# Redirection number
# ITU-T Q.763, section 3.46
#------------------------------------------------------------------------------#

class RedirectionNum(CalledPartyNum):
    pass


#------------------------------------------------------------------------------#
# Redirection number restriction
# ITU-T Q.763, section 3.47
#------------------------------------------------------------------------------#

_PresentationRestrictedInd_dict = {
    0 : 'presentation allowed',
    1 : 'presentation restricted',
    2 : 'spare',
    3 : 'spare'
    }


class RedirectNumRestriction(Envelope):
    _GEN = (
        Uint('spare', bl=6, rep=REPR_HEX),
        Uint('PresentationRestrictedInd', bl=2, dic=_PresentationRestrictedInd_dict)
        )


#------------------------------------------------------------------------------#
# Remote operations (national use)
# ITU-T Q.763, section 3.48
#------------------------------------------------------------------------------#

_ProtocolProfile_dict = {
    17 : 'remote operations protocol'
    }


class RemoteOperations(Envelope):
    _GEN = (
        Uint('ext', val=1, bl=1),
        Uint('spare', bl=2, rep=REPR_HEX),
        Uint('ProtocolProfile', bl=5, dic=_ProtocolProfile_dict),
        Buf('Components', val=b'', rep=REPR_HEX) # actually contains BER-encoded TCAP components
        )


#------------------------------------------------------------------------------#
# Service activation
# ITU-T Q.763, section 3.49
#------------------------------------------------------------------------------#

_FeatureCode_dict = {
0 : 'spare',
1 : 'call transfer',
255 : 'extension'
}

for i in range(2, 124):
    _FeatureCode_dict[i] = 'reserved for international use'

for i in range(124, 255):
    _FeatureCode_dict[i] = 'reserved for national use'


class ServiceActivation(Array):
    _GEN = Uint8('FeatureCode', dic=_FeatureCode_dict)


#------------------------------------------------------------------------------#
# Signalling point code (national use)
# ITU-T Q.763, section 3.50
#------------------------------------------------------------------------------#

class SignallingPointCode(Uint16LE):
    pass


#------------------------------------------------------------------------------#
# Subsequent number
# ITU-T Q.763, section 3.51
#------------------------------------------------------------------------------#

class SubsequentNum(ISUPNum):
    _GEN = (
        Uint('OE', bl=1, dic=_NumOE_dict),
        Uint('spare', bl=7, rep=REPR_HEX),
        ISUPBufBCD('Num', val=b'')
        )


#------------------------------------------------------------------------------#
# Suspend/resume indicators
# ITU-T Q.763, section 3.52
#------------------------------------------------------------------------------#

_SuspendResumeInd_dict = {
    0 : 'ISDN subscriber initiated',
    1 : 'network initiated'
    }


class SuspendResumeInd(Envelope):
    _GEN = (
        Uint('spare', bl=7, rep=REPR_HEX),
        Uint('Value', bl=1, dic=_SuspendResumeInd_dict)
        )


#------------------------------------------------------------------------------#
# Transit network selection (national use)
# ITU-T Q.763, section 3.53
#------------------------------------------------------------------------------#


_ITUTNetworkIdentPlan_dict = {
    0 : 'unknown',
    3 : 'public data network identification code (DNIC), ITU-T Recommendation X.121',
    6 : 'public land Mobile Network Identification Code (MNIC), ITU-T Recommendation E.212'
    }

class TransitNetworkSel(ISUPNum):
    _GEN = (
        Uint('OE', bl=1, dic=_NumOE_dict),
        Uint('TypeOfNetworkIdent', val=1, bl=3, dic=_TypeOfNetwork_dict),
        Uint('NetworkIdentPlan', val=6, bl=4),
        ISUPBufBCD('Num', val=b'')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['NetworkIdentPlan'].set_dicauto(lambda: _ITUTNetworkIdentPlan_dict if self['TypeOfNetworkIdent'].get_val() == 0 else {})


#------------------------------------------------------------------------------#
# Transmission medium requirement
# ITU-T Q.763, section 3.54
#------------------------------------------------------------------------------#

_TransmissionMediumReq_dict = {
    0 : 'speech',
    1 : 'spare',
    2 : '64 kbit/s unrestricted',
    3 : '3.1 kHz audio',
    4 : 'reserved for alternate speech (service 2)/64 kbit/s unrestricted (service 1)',
    5 : 'reserved for alternate 64 kbit/s unrestricted (service 1)/speech (service 2)',
    6 : '64 kbit/s preferred',
    7 : '2 × 64 kbit/s unrestricted',
    8 : '384 kbit/s unrestricted',
    9 : '1536 kbit/s unrestricted',
    10 : '1920 kbit/s unrestricted',
    16 : '3 × 64 kbit/s unrestricted',
    17 : '4 × 64 kbit/s unrestricted',
    18 : '5 × 64 kbit/s unrestricted',
    19 : 'spare',
    20 : '7 × 64 kbit/s unrestricted',
    21 : '8 × 64 kbit/s unrestricted',
    22 : '9 × 64 kbit/s unrestricted',
    23 : '10 × 64 kbit/s unrestricted',
    24 : '11 × 64 kbit/s unrestricted',
    25 : '12 × 64 kbit/s unrestricted',
    26 : '13 × 64 kbit/s unrestricted',
    27 : '14 × 64 kbit/s unrestricted',
    28 : '15 × 64 kbit/s unrestricted',
    29 : '16 × 64 kbit/s unrestricted',
    30 : '17 × 64 kbit/s unrestricted',
    31 : '18 × 64 kbit/s unrestricted',
    32 : '19 × 64 kbit/s unrestricted',
    33 : '20 × 64 kbit/s unrestricted',
    34 : '21 × 64 kbit/s unrestricted',
    35 : '22 × 64 kbit/s unrestricted',
    36 : '23 × 64 kbit/s unrestricted',
    37 : 'spare',
    38 : '25 × 64 kbit/s unrestricted',
    39 : '26 × 64 kbit/s unrestricted',
    40 : '27 × 64 kbit/s unrestricted',
    41 : '28 × 64 kbit/s unrestricted',
    42 : '29 × 64 kbit/s unrestricted'
    }


class TransmissionMediumReq(Uint8):
    _dic = _TransmissionMediumReq_dict


#------------------------------------------------------------------------------#
# Transmission medium requirement prime
# ITU-T Q.763, section 3.55
#------------------------------------------------------------------------------#

_TransmissionMediumReqPrime_dict = {
    0 : 'speech',
    1 : 'spare',
    2 : 'reserved for 64 kbit/s unrestricted',
    3 : '3.1 kHz audio',
    4 : 'reserved for alternate speech (service 2)/64 kbit/s unrestricted (service 1)',
    5 : 'reserved for alternate 64 kbit/s unrestricted (service 1)/speech (service 2)',
    6 : 'reserved for 64 kbit/s preferred',
    7 : 'reserved for 2 × 64 kbit/s unrestricted',
    8 : 'reserved for 384 kbit/s unrestricted',
    9 : 'reserved for 1536 kbit/s unrestricted',
    10 : 'reserved for 1920 kbit/s unrestricted'
    }


class TransmissionMediumReqPrime(Uint8):
    _dic = _TransmissionMediumReqPrime_dict


#------------------------------------------------------------------------------#
# Transmission medium used
# ITU-T Q.763, section 3.56
#------------------------------------------------------------------------------#

class TransmissionMediumUsed(TransmissionMediumReqPrime):
    pass


#------------------------------------------------------------------------------#
# User service information
# ITU-T Q.763, section 3.57
#------------------------------------------------------------------------------#
# see Q.931 Bearer capability information element
 
_InfoTransferCap_dict = {
    0 : 'Speech',
    8 : 'Unrestricted digital information',
    9 : 'Restricted digital information',
    16 : '3.1 kHz audio',
    17 : 'Unrestricted digital information with tones/announcements',
    24 : 'Video'
    }

_TransferMode_dict = {
    0 : 'Circuit mode',
    1 : 'Packet mode'
    }

_InfoTransferRate_dict = {
    0 : 'packet-mode call',
    16 : '64 kbit/s',
    17 : '2 × 64 kbit/s',
    19 : '384 kbit/s',
    21 : '1536 kbit/s',
    23 : '1920 kbit/s',
    24 : 'Multirate (64 kbit/s base rate)'
    }


class UserServiceInfo(Envelope):
    ENV_SEL_TRANS = False
    _GEN = (
        Uint('ext', val=1, bl=1),
        Uint('CodingStd', bl=2, dic=_CodingStd_dict),
        Uint('InfoTransferCap', bl=5, dic=_InfoTransferCap_dict),
        Uint('ext', val=1, bl=1),
        Uint('TransferMode', bl=2, dic=_TransferMode_dict),
        Uint('InfoTransferRate', bl=5, dic=_InfoTransferRate_dict),
        Uint8('RateMultiplier'),
        Uint('ext', val=1, bl=1),
        Uint('LayerIdent1', bl=2),
        Uint('UserInfoLayer1Prot', bl=5),
        Uint('ext', val=1, bl=1),
        Uint('LayerIdent2', bl=2),
        Uint('UserInfoLayer2Prot', bl=5),
        Uint('ext', val=1, bl=1),
        Uint('LayerIdent3', bl=2),
        Uint('UserInfoLayer3Prot', bl=5),
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['RateMultiplier'].set_transauto(lambda: True if self['InfoTransferRate'].get_val() != 24 else False)
    
    def _from_char(self, char):
        if self.get_trans():
            return
        # truncate char if length automation is set
        if self._blauto is not None:
            char_lb = char._len_bit
            char._len_bit = char._cur + self._blauto()
            if char._len_bit > char_lb:
                raise(EltErr('{0} [_from_char]: bit length overflow'.format(self._name)))
        #
        for i in range(0, 7):
            self[i]._from_char(char)
        clen = char.len_byte()
        if clen < 3:
            self[13].set_trans(True)
            self[14].set_trans(True)
            self[15].set_trans(True)
        if clen < 2:
            self[10].set_trans(True)
            self[11].set_trans(True)
            self[12].set_trans(True)
        if clen == 0:
            self[7].set_trans(True)
            self[8].set_trans(True)
            self[9].set_trans(True)
        for i in range(7, 16):
            self[i]._from_char(char)
        #
        if self._blauto is not None:
            char._len_bit = char_lb


#------------------------------------------------------------------------------#
# User service information prime
# ITU-T Q.763, section 3.58
#------------------------------------------------------------------------------#

class UserServiceInfoPrime(UserServiceInfo):
    pass


#------------------------------------------------------------------------------#
# User teleservice information
# ITU-T Q.763, section 3.59
#------------------------------------------------------------------------------#

class UserTeleserviceInfo(Envelope):
    _GEN = (
        Uint('ext', val=1, bl=1),
        Uint('CodingStd', bl=2, dic=_CodingStd_dict),
        Uint('Interpretation', bl=3),
        Uint('Presentation', bl=2),
        Uint('ext', val=1, bl=1),
        Uint('HighLayerCharIdent', bl=7),
        Uint('ext', val=1, bl=1),
        Uint('ExtLayerCharIdent', bl=7)
        )


#------------------------------------------------------------------------------#
# User-to-user indicators
# ITU-T Q.763, section 3.60
#------------------------------------------------------------------------------#

# for request
_Service3Req_dict = {
    0 : 'no information',
    1 : 'spare',
    2 : 'request, not essential',
    3 : 'request, essential'
    }

_Service2Req_dict = {
    0 : 'no information',
    1 : 'spare',
    2 : 'request, not essential',
    3 : 'request, essential'
    }

_Service1Req_dict = {
    0 : 'no information',
    1 : 'spare',
    2 : 'request, not essential',
    3 : 'request, essential'
    }

# for response
_NetworkDiscardInd_dict = {
    0 : 'no information',
    1 : 'user-to-user information discarded by the network'
    }

_Service3Resp_dict = {
    0 : 'no information',
    1 : 'not provided',
    2 : 'provided',
    3 : 'spare'
    }

_Service2Resp_dict = {
    0 : 'no information',
    1 : 'not provided',
    2 : 'provided',
    3 : 'spare'
    }

_Service1Resp_dict = {
    0 : 'no information',
    1 : 'not provided',
    2 : 'provided',
    3 : 'spare'
    }


class UserToUserInd(Envelope):
    _GEN = (
        Uint('NetworkDiscardInd', bl=1),
        Uint('Service3', bl=2),
        Uint('Service2', bl=2),
        Uint('Service1', bl=2),
        Uint('Type', bl=1, dic={0:'request', 1:'response'})
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['NetworkDiscardInd'].set_dicauto(lambda: _NetworkDiscardInd_dict if self['Type'].get_val() else {})
        self['Service3'].set_dicauto(lambda: _Service3Resp_dict if self['Type'].get_val() else _Service3Req_dict)
        self['Service2'].set_dicauto(lambda: _Service2Resp_dict if self['Type'].get_val() else _Service2Req_dict)
        self['Service1'].set_dicauto(lambda: _Service1Resp_dict if self['Type'].get_val() else _Service1Req_dict)


#------------------------------------------------------------------------------#
# User-to-user information
# ITU-T Q.763, section 3.61
#------------------------------------------------------------------------------#
# TODO: understand and check how to leverage Q.931 to have a proper content here

class UserToUserInfo(Buf):
    rep = REPR_HEX


#------------------------------------------------------------------------------#
# Backward GVNS
# ITU-T Q.763, section 3.62
#------------------------------------------------------------------------------#

_TerminatingAccessInd_dict = {
    0 : 'no information',
    1 : 'dedicated terminating access',
    2 : 'switched terminating access',
    3 : 'spare'
    }


class BackwardGVNS(Envelope):
    _GEN = (
        Uint('ext', val=1, bl=1),
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('TerminatingAccessInd', bl=2, dic=_TerminatingAccessInd_dict)
        )


#------------------------------------------------------------------------------#
# CCSS
# ITU-T Q.763, section 3.63
#------------------------------------------------------------------------------#

_CCSSCallInd_dict = {
    0 : 'no indication',
    1 : 'CCSS call'
    }


class CCSS(Envelope):
    _GEN = (
        Uint('spare', bl=7, rep=REPR_HEX),
        Uint('CCSSCallInd', bl=1, dic=_CCSSCallInd_dict)
        )


#------------------------------------------------------------------------------#
# Call transfer number
# ITU-T Q.763, section 3.64
#------------------------------------------------------------------------------#

class CallTransferNum(ISUPNum):
    _GEN = (
        Uint('OE', bl=1, dic=_NumOE_dict),
        Uint('NAI', val=1, bl=7, dic=_NumNAI_dict),
        Uint('spare', bl=1),
        Uint('NumPlan', bl=3, dic=_NumPlan_dict),
        Uint('AddrPresInd', bl=2, dic=_AddrPresInd_dict),
        Uint('ScreeningInd', bl=2, dic=_ScreeningInd2_dict),
        ISUPBufBCD('Num', val=b'')
        )


#------------------------------------------------------------------------------#
# Call transfer reference
# ITU-T Q.763, section 3.65
#------------------------------------------------------------------------------#

class CallTransferRef(Uint8):
    pass


#------------------------------------------------------------------------------#
# Forward GVNS
# ITU-T Q.763, section 3.66
#------------------------------------------------------------------------------#

class _ForwardGVNS_Num(ISUPNum):
    _GEN = (
        Uint('OE', bl=1, dic=_NumOE_dict),
        Uint('spare', bl=3),
        Uint('Len', bl=4),
        ISUPBufBCD('Num', val=b'')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda: self['Num'].get_len())
        self['Num'].set_blauto(lambda: self['Len'].get_val()<<3)


class _OPSP(_ForwardGVNS_Num):
    pass


class _GUG(_ForwardGVNS_Num):
    pass


class _TRNR(ISUPNum):
    _GEN = (
        Uint('OE', bl=1, dic=_NumOE_dict),
        Uint('NumPlan', bl=3, dic=_NumPlan_dict),
        Uint('Len', bl=4),
        Uint('spare', bl=1),
        Uint('NAI', val=1, bl=7, dic=_NumNAI_dict),
        ISUPBufBCD('Num', val=b'')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        # TODO: not sure NAI is always there
        self['Len'].set_valauto(lambda: 1+self['Num'].get_len())
        self['Num'].set_blauto(lambda: (self['Len'].get_val()-1)<<3)


class ForwardGVNS(Envelope):
    _GEN = (
        _OPSP('OriginatingParticipatingServiceProvider'),
        _GUG('GVNSUserGroup'),
        _TRNR('TerminatingNetworkRoutingNumber')
        )


#------------------------------------------------------------------------------#
# Loop prevention indicators
# ITU-T Q.763, section 3.67
#------------------------------------------------------------------------------#

_ResponseInd_dict = {
    0 : 'insufficient information (note)',
    1 : 'no loop exists',
    2 : 'simultaneous transfer',
    3 : 'spare'
    }


class LoopPreventionInd(Envelope):
    _GEN = (
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('ResponseInd', bl=2),
        Uint('Type', bl=1, dic={0:'request', 1:'response'})
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['ResponseInd'].set_dicauto(lambda: _ResponseInd_dict if self['Type'].get_val() else {})


#------------------------------------------------------------------------------#
# Network management controls
# ITU-T Q.763, section 3.68
#------------------------------------------------------------------------------#

_TARInd_dict = {
    0 : 'no indication',
    1 : 'TAR controlled call'
    }

class NetworkMgmtControls(Envelope):
    _GEN = (
        Uint('ext', val=1, bl=1),
        Uint('spare', bl=6, rep=REPR_HEX),
        Uint('TARInd', bl=1, dic=_TARInd_dict)
        )


#------------------------------------------------------------------------------#
# Circuit assignment map
# ITU-T Q.763, section 3.69
#------------------------------------------------------------------------------#

_MapType_dict = {
    1 : '1544 kbit/s digital path map format (64 kbit/s base rate)',
    2 : '2048 kbit/s digital path map format (64 kbit/s base rate)'
    }

class CircuitAssignMap(Envelope):
    _GEN = (
        Uint('spare', bl=2, rep=REPR_HEX),
        Uint('MapType', bl=6, dic=_MapType_dict),
        Uint32LE('Map', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Correlation id
# ITU-T Q.763, section 3.70
#------------------------------------------------------------------------------#
# TODO: understand and check how to leverage Q.1218 (IN CS.1) to have a proper content here
# CorrelationID ::= OCTET STRING (SIZE (minDigitsLength..maxDigitsLength))

class CorrelationID(Buf):
    rep=REPR_HEX


#------------------------------------------------------------------------------#
# SCF id
# ITU-T Q.763, section 3.71
#------------------------------------------------------------------------------#
# TODO: understand and check how to leverage Q.1218 (IN CS.1) to have a proper content here
# ScfID ::= OCTET STRING (SIZE (minScfIDLength..maxScfIDLength))

class ScfID(Buf):
    rep=REPR_HEX


#------------------------------------------------------------------------------#
# Call diversion treatment indicators
# ITU-T Q.763, section 3.72
#------------------------------------------------------------------------------#

_CallToBeDivertedInd_dict = {
    0 : 'no indication',
    1 : 'call diversion allowed',
    2 : 'call diversion not allowed',
    3 : 'spare'
    }


class CallDiversionTreatmentInd(Envelope):
    _GEN = (
        Uint('ext', val=1, bl=1),
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('CallToBeDivertedInd', bl=2, dic=_CallToBeDivertedInd_dict)
        )


#------------------------------------------------------------------------------#
# Called IN number
# ITU-T Q.763, section 3.73
#------------------------------------------------------------------------------#

class CalledINNum(OriginalCalledNum):
    pass


#------------------------------------------------------------------------------#
# Call offering treatment indicators
# ITU-T Q.763, section 3.74
#------------------------------------------------------------------------------#

_CallToBeOfferedInd_dict = {
    0 : 'no indication',
    1 : 'call offering not allowed',
    2 : 'call offering allowed',
    3 : 'spare'
    }


class CallOfferingTreatmentInd(Envelope):
    _GEN = (
        Uint('ext', val=1, bl=1),
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('CallToBeOfferedInd', bl=2, dic=_CallToBeOfferedInd_dict)
        )


#------------------------------------------------------------------------------#
# Charged party identification (national use)
# ITU-T Q.763, section 3.75
#------------------------------------------------------------------------------#
# TODO: understand and check how to leverage Q.1218 (IN CS.1) and Q.1228 to have a proper content here

class ChargedPartyIdent(Buf):
    rep = REPR_HEX


#------------------------------------------------------------------------------#
# Conference treatment indicators
# ITU-T Q.763, section 3.76
#------------------------------------------------------------------------------#

_ConferenceAcceptInd_dict = {
    0 : 'no indication',
    1 : 'accept conference request',
    2 : 'reject conference request',
    3 : 'spare'
    }


class ConferenceTreatmentInd(Envelope):
    _GEN = (
        Uint('ext', val=1, bl=1),
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('ConferenceAcceptInd', bl=2, dic=_ConferenceAcceptInd_dict)
        )


#------------------------------------------------------------------------------#
# Display information
# ITU-T Q.763, section 3.77
#------------------------------------------------------------------------------#
# Q.931, section 4.5.16, Display

class DisplayInfo(Envelope):
    _GEN = (
        Uint8('IE', val=40),
        Uint8('Len'),
        Buf('Disp', val=b'')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda: self['Disp'].get_len())
        self['Disp'].set_blauto(lambda: self['Len'].get_val()<<3)


#------------------------------------------------------------------------------#
# UID action indicators
# ITU-T Q.763, section 3.78
#------------------------------------------------------------------------------#

_T9TimerInsInd_dict = {
    0 : 'no indication',
    1 : 'stop or do not start T9 timer'
    }

_ThroughConnectionInsInd_dict = {
    0 : 'no indication',
    1 : 'through-connect in both directions'
    }


class UIDActionInd(Envelope):
    _GEN = (
        Uint('ext', val=1, bl=1),
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('T9TimerInsInd', bl=1, dic=_T9TimerInsInd_dict),
        Uint('ThroughConnectionInsInd', bl=1, dic=_ThroughConnectionInsInd_dict)
        )


#------------------------------------------------------------------------------#
# UID capability indicators
# ITU-T Q.763, section 3.79
#------------------------------------------------------------------------------#

_T9TimerInd_dict = {
    0 : 'no indication',
    1 : 'stopping of T9 timer possible'
    }

_ThroughConnectionInd_dict = {
    0 : 'no indication',
    1 : 'through-connection modification possible'
    }


class UIDCapInd(Envelope):
    _GEN = (
        Uint('ext', val=1, bl=1),
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('T9TimerInd', bl=1, dic=_T9TimerInd_dict),
        Uint('ThroughConnectionInd', bl=1, dic=_ThroughConnectionInd_dict)
        )


#------------------------------------------------------------------------------#
# Hop counter
# ITU-T Q.763, section 3.80
#------------------------------------------------------------------------------#

class HopCounter(Envelope):
    _GEN = (
        Uint('spare', bl=3, rep=REPR_HEX),
        Uint('Value', bl=5)
        )


#------------------------------------------------------------------------------#
# Collect call request
# ITU-T Q.763, section 3.81
#------------------------------------------------------------------------------#

_CollectCallReqInd_dict = {
    0 : 'no indication',
    1 : 'collect call requested'
    }


class CollectCallReq(Envelope):
    _GEN = (
        Uint('spare', bl=7, rep=REPR_HEX),
        Uint('Value', bl=1, dic=_CollectCallReqInd_dict)
        )


#------------------------------------------------------------------------------#
# Application transport parameter (ATP)
# ITU-T Q.763, section 3.82
#------------------------------------------------------------------------------#

_AppCtxtIdent_dict = {
    0 : 'Unidentified Context and Error Handling (UCEH) ASE',
    1 : 'PSS1 ASE (VPN)',
    2 : 'spare',
    3 : 'Charging ASE',
    4 : 'GAT'
    }

for i in range(64, 128):
    _AppCtxtIdent_dict[i] = 'reserved for non-standardized applications'

_SNI_dict = {
    0 : 'do not send notification',
    1 : 'send notification'
    }

_RCI_dict = {
    0 : 'do not release call',
    1 : 'release call'
    }

_SequenceInd_dict = {
    0 : 'subsequent segment to first segment',
    1 : 'new sequence'
    }


class AppTransportParam(Envelope):
    _GEN = (
        Uint('ext', val=1, bl=1),
        Uint('AppCtxtIdent', bl=7, dic=_AppCtxtIdent_dict),
        Uint('ext', val=1, bl=1),
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('SNI', bl=1, dic=_SNI_dict),
        Uint('RCI', bl=1, dic=_RCI_dict),
        Uint('ext', val=1, bl=1),
        Uint('SI', bl=1, dic=_SequenceInd_dict),
        Uint('APMSegmentationInd', bl=6),
        ExtByte('SegmentationLocalRef'),
        Buf('EncapsulatedAppInfo', val=b'\0', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['SegmentationLocalRef'].set_transauto(lambda: True if self[6].get_val() else False)


#------------------------------------------------------------------------------#
# CCNR possible indicator
# ITU-T Q.763, section 3.83
#------------------------------------------------------------------------------#

_CCNRPossibleInd_dict = {
    0 : 'CCNR not possible',
    1 : 'CCNR possible'
    }


class CCNRPossibleInd(Envelope):
    _GEN = (
        Uint('spare', bl=7, rep=REPR_HEX),
        Uint('Value', bl=1, dic=_CCNRPossibleInd_dict)
        )


#------------------------------------------------------------------------------#
# Pivot capability
# ITU-T Q.763, section 3.84
#------------------------------------------------------------------------------#

_InterworkToRedirectInd_dict = {
    0 : 'allowed (forward)',
    1 : 'not allowed (forward)'
    }

_PivotPossibleInd_dict = {
    0 : 'no indication',
    1 : 'pivot routing possible before ACM',
    2 : 'pivot routing possible before ANM',
    3 : 'pivot routing possible any time during the call'
    }


class PivotCap(Envelope):
    _GEN = (
        Uint('ext', val=1, bl=1),
        Uint('InterworkToRedirectInd', bl=1, dic=_InterworkToRedirectInd_dict),
        Uint('spare', bl=3),
        Uint('PivotPossibleInd', bl=3, dic=_PivotPossibleInd_dict)
        )


#------------------------------------------------------------------------------#
# Pivot routing indicators
# ITU-T Q.763, section 3.85
#------------------------------------------------------------------------------#

_PivotRoutingInd_dict = {
    0 : 'no indication',
    1 : 'pivot request',
    2 : 'cancel pivot request',
    3 : 'pivot request failure',
    4 : 'interworking to redirection prohibited (backward) (national use)',
    }


class PivotRoutingInd(Envelope):
    _GEN = (
        Uint('ext', val=1, bl=1),
        Uint('Value', bl=7, dic=_PivotRoutingInd_dict)
        )


#------------------------------------------------------------------------------#
# Called directory number (national use)
# ITU-T Q.763, section 3.86
#------------------------------------------------------------------------------#

class CalledDirectoryNum(ISUPNum):
    _GEN = (
        Uint('OE', bl=1, dic=_NumOE_dict),
        Uint('NAI', val=1, bl=7, dic=_NumNAI_dict),
        Uint('INN', bl=1, dic=_NumINN_dict),
        Uint('NumPlan', bl=3, dic=_NumPlan_dict),
        Uint('spare', bl=4, rep=REPR_HEX),
        ISUPBufBCD('Num', val=b'')
        )


#------------------------------------------------------------------------------#
# Original Called IN number
# ITU-T Q.763, section 3.87
#------------------------------------------------------------------------------#

class OriginalCalledINNum(OriginalCalledNum):
    pass


#------------------------------------------------------------------------------#
# Calling geodetic location
# ITU-T Q.763, section 3.88
#------------------------------------------------------------------------------#

_LPRI_dict = {
    0 : 'presentation allowed',
    1 : 'presentation restricted',
    2 : 'location not available (Note)',
    3 : 'spare'
    }

_TypeOfShape_dict = {
    0 : 'ellipsoid point',
    1 : 'ellipsoid point with uncertainty',
    2 : 'point with altitude and uncertainty',
    3 : 'ellipse on the ellipsoid',
    4 : 'ellipsoid circle sector',
    5 : 'polygon',
    127 : 'reserved for future expansion'
    }

for i in range(64, 127):
    _TypeOfShape_dict[i] = 'reserved for national use'


class _ShapeEllipsoidPoint(Envelope):
    _GEN = (
        Uint('LatSign', bl=1, dic={0:'North', 1:'South'}),
        Uint('LatDegrees', bl=23),
        Uint24('LongDegrees')
        )


class _ShapeEllipsoidPointUncertainty(Envelope):
    _GEN = (
        Uint('LatSign', bl=1, dic={0:'North', 1:'South'}),
        Uint('LatDegrees', bl=23),
        Uint24('LongDegrees'),
        Uint('spare', bl=1),
        Uint('UncertaintyCode', bl=7),
        Uint('spare', bl=1),
        Uint('Confidence', bl=7)
        )


class _ShapePointAltitudeUncertainty(Envelope):
    _GEN = (
        Uint('LatSign', bl=1, dic={0:'North', 1:'South'}),
        Uint('LatDegrees', bl=23),
        Uint24('LongDegrees'),
        Uint('spare', bl=1),
        Uint('UncertaintyCode', bl=7),
        Uint('AltSign', bl=1, dic={0:'above the ellipsoid', 1:'below the ellipsoid'}),
        Uint('Alt', bl=15),
        Uint('spare', bl=1),
        Uint('UncertaintyCode', bl=7),
        Uint('spare', bl=1),
        Uint('Confidence', bl=7)
        )


class _ShapeEllipseEllipsoid(Envelope):
    _GEN = (
        Uint('LatSign', bl=1, dic={0:'North', 1:'South'}),
        Uint('LatDegrees', bl=23),
        Uint24('LongDegrees'),
        Uint('spare', bl=1),
        Uint('MajorRadius', bl=7),
        Uint('spare', bl=1),
        Uint('MinorRadius', bl=7),
        Uint8('Orientation'),
        Uint('spare', bl=1),
        Uint('Confidence', bl=7)
        )


class _ShapeEllipsoidCircle(Envelope):
    _GEN = (
        Uint('LatSign', bl=1, dic={0:'North', 1:'South'}),
        Uint('LatDegrees', bl=23),
        Uint24('LongDegrees'),
        Uint('spare', bl=1),
        Uint('Radius', bl=7),
        Uint8('Offset'),
        Uint8('IncludedAngle'),
        Uint('spare', bl=1),
        Uint('Confidence', bl=7)
        )


class _ShapePolygon(Envelope):
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('Num', bl=4),
        Sequence('Points', GEN=_ShapeEllipsoidPoint('EllipsoidPoint')),
        Uint('spare', bl=1),
        Uint('Confidence', bl=7)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Num'].set_valauto(lambda: self['Points'].get_num())
        self['Points'].set_numauto(lambda: self['Num'].get_val())


class CallingGeodeticLocation(Envelope):
    _GEN = (
        Uint('spare', bl=4),
        Uint('LPRI', bl=2, dic=_LPRI_dict),
        Uint('Screening', bl=2, dic=_ScreeningInd2_dict),
        Uint('ext', val=1, bl=1),
        Uint('TypeOfShape', bl=7, dic=_TypeOfShape_dict),
        Alt('Shape', GEN={
            0 : _ShapeEllipsoidPoint('EllipsoidPoint'),
            1 : _ShapeEllipsoidPointUncertainty('EllipsoidPointUncertainty'),
            2 : _ShapePointAltitudeUncertainty('PointAltitudeUncertainty'),
            3 : _ShapeEllipseEllipsoid('EllipseEllipsoid'),
            4 : _ShapeEllipsoidCircle('EllipsoidCircle'),
            5 : _ShapePolygon('Polygon'),
            },
            DEFAULT=Buf('unknown', rep=REPR_HEX),
            sel=lambda self: self.get_env()['TypeOfShape'].get_val())
        )


#------------------------------------------------------------------------------#
# HTR information
# ITU-T Q.763, section 3.89
#------------------------------------------------------------------------------#

class HTRInfo(ISUPNum):
    _GEN = (
        Uint('OE', bl=1, dic=_NumOE_dict),
        Uint('NAI', val=1, bl=7, dic=_NumNAI_dict),
        Uint('spare', bl=1),
        Uint('NumPlan', bl=3, dic=_NumPlan_dict),
        Uint('spare', bl=4, rep=REPR_HEX),
        ISUPBufBCD('Num', val=b'')
        )


#------------------------------------------------------------------------------#
# Network routing number (national use)
# ITU-T Q.763, section 3.90
#------------------------------------------------------------------------------#

_NumNAI2_dict = {
    1 : 'network routing number in national (significant) number format (national use)',
    2 : 'network routing number in network specific number format (national use)'
    }

for i in range(11, 16):
    _NumNAI2_dict[i] = 'reserved for national use'


class NetworkRoutingNum(ISUPNum):
    _GEN = (
        Uint('OE', bl=1, dic=_NumOE_dict),
        Uint('NumPlan', bl=3, dic=_NumPlan_dict),
        Uint('NAI', val=1, bl=4, dic=_NumNAI2_dict),
        ISUPBufBCD('Num', val=b'')
        )


#------------------------------------------------------------------------------#
# Query on release capability (network option)
# ITU-T Q.763, section 3.91
#------------------------------------------------------------------------------#

_QoRCap_dict = {
    0 : 'no indication',
    1 : 'QoR support'
    }


class QueryOnReleaseCap(Envelope):
    _GEN = (
        Uint('ext', val=1, bl=1),
        Uint('spare', bl=6, rep=REPR_HEX),
        Uint('Value', bl=1, dic=_QoRCap_dict)
        )


#------------------------------------------------------------------------------#
# Pivot status (national use)
# ITU-T Q.763, section 3.92
#------------------------------------------------------------------------------#

_PivotStatus_dict = {
    0 : 'not used',
    1 : 'acknowledgment of pivot routing',
    2 : 'pivot routing will not be invoked',
    3 : 'spare'
    }


class PivotStatus(Envelope):
    _GEN = (
        Uint('ext', val=1, bl=1),
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('Value', bl=3, dic=_PivotStatus_dict)
        )


#------------------------------------------------------------------------------#
# Pivot Counter
# ITU-T Q.763, section 3.93
#------------------------------------------------------------------------------#

class PivotCounter(Envelope):
    _GEN = (
        Uint('spare', bl=3, rep=REPR_HEX),
        Uint('Value', bl=5)
        )


#------------------------------------------------------------------------------#
# Pivot routing forward information
# ITU-T Q.763, section 3.94
#------------------------------------------------------------------------------#
# TODO: implement specific Information Type values

_PRFITag_dict = {
    0 : 'not used',
    1 : 'return to invoking exchange possible (national use)',
    2 : 'return to invoking exchange call identifier (national use)',
    3 : 'performing pivot indicator',
    4 : 'invoking pivot reason'
    }


class PRFI_TLV(Envelope):
    _GEN = (
        Uint8('Tag', dic=_PRFITag_dict),
        Uint8('Len'),
        Buf('Val', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda: self['Val'].get_len())
        self['Val'].set_blauto(lambda: self['Len'].get_val()<<3)


class PivotRoutingForwardInfo(Sequence):
    _GEN = PRFI_TLV('InfoType')

 
#------------------------------------------------------------------------------#
# Pivot routing backward information
# ITU-T Q.763, section 3.95
#------------------------------------------------------------------------------#
# TODO: implement specific Information Type values

_PRBITag_dict = {
    0 : 'not used',
    1 : 'return to invoking exchange duration',
    2 : 'return to invoking exchange call identifier',
    3 : 'invoking pivot reason'
    }


class PRBI_TLV(Envelope):
    _GEN = (
        Uint8('Tag', dic=_PRBITag_dict),
        Uint8('Len'),
        Buf('Val', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda: self['Val'].get_len())
        self['Val'].set_blauto(lambda: self['Len'].get_val()<<3)


class PivotRoutingBackwardInfo(Sequence):
    _GEN = PRBI_TLV('InfoType')


#------------------------------------------------------------------------------#
# Redirect capability (national use)
# ITU-T Q.763, section 3.96
#------------------------------------------------------------------------------#

_RedirectCap_dict = {
    0 : 'not used',
    1 : 'redirect possible before ACM',
    2 : 'redirect possible before ANM',
    3 : 'redirect possible at any time during the call'
    }

class RedirectCap(Envelope):
    _GEN = (
        Uint('ext', val=1, bl=1),
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('Value', bl=3, dic=_RedirectCap_dict)
        )


#------------------------------------------------------------------------------#
# Redirect counter (national use)
# ITU-T Q.763, section 3.97
#------------------------------------------------------------------------------#

class RedirectCounter(Envelope):
    _GEN = (
        Uint('spare', bl=3, rep=REPR_HEX),
        Uint('Value', bl=5)
        )


#------------------------------------------------------------------------------#
# Redirect status (national use)
# ITU-T Q.763, section 3.98
#------------------------------------------------------------------------------#

_RedirectStatus_dict = {
    0 : 'not used',
    1 : 'acknowledgment of redirection',
    2 : 'redirection will not be invoked',
    3 : 'spare'
    }


class RedirectStatus(Envelope):
    _GEN = (
        Uint('ext', val=1, bl=1),
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('Value', bl=2, dic=_RedirectStatus_dict)
        )


#------------------------------------------------------------------------------#
# Redirect forward information (national use)
# ITU-T Q.763, section 3.99
#------------------------------------------------------------------------------#
# TODO: implement specific Information Type values

_RFITag_dict = {
    0 : 'not used',
    1 : 'return to invoking exchange possible',
    2 : 'return to invoking exchange call identifier',
    3 : 'performing redirect indicator',
    4 : 'invoking redirect reason'
    }


class RFI_TLV(Envelope):
    _GEN = (
        Uint8('Tag', dic=_RFITag_dict),
        Uint8('Len'),
        Buf('Val', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda: self['Val'].get_len())
        self['Val'].set_blauto(lambda: self['Len'].get_val()<<3)


class RedirectForwardInfo(Sequence):
    _GEN = RFI_TLV('InfoType')


#------------------------------------------------------------------------------#
# Redirect backward information (national use)
# ITU-T Q.763, section 3.100
#------------------------------------------------------------------------------#
# TODO: implement specific Information Type values

_RBITag_dict = {
    0 : 'not used',
    1 : 'return to invoking exchange possible',
    2 : 'return to invoking exchange call identifier',
    3 : 'invoking redirect reason'
    }


class RBI_TLV(Envelope):
    _GEN = (
        Uint8('Tag', dic=_RBITag_dict),
        Uint8('Len'),
        Buf('Val', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda: self['Val'].get_len())
        self['Val'].set_blauto(lambda: self['Len'].get_val()<<3)


class RedirectBackwardInfo(Sequence):
    _GEN = RBI_TLV('InfoType')


#------------------------------------------------------------------------------#
# Number portability forward information (network option)
# ITU-T Q.763, section 3.101
#------------------------------------------------------------------------------#

_NumPortabilityForwardInfo_dict = {
    0 : 'no indication',
    1 : 'number portability query not done for called number',
    2 : 'number portability query done for called number, non-ported called subscriber',
    3 : 'number portability query done for called number, ported called subscriber'
    }


class NumPortabilityForwardInfo(Envelope):
    _GEN = (
        Uint('ext', val=1, bl=1),
        Uint('spare', bl=3, rep=REPR_HEX),
        Uint('Value', bl=4, dic=_NumPortabilityForwardInfo_dict)
        )


#------------------------------------------------------------------------------#
# ISDN user part messages
# ITU-T Q.763, section 4
#------------------------------------------------------------------------------#

class AddressComplete(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x6, dic=ISUPType_dict),
        BackwardCallInd(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Opt'),
            )),
        ISUPOpt('Opt', GEN=(
            Optional(OptBackwardCallInd(), 41),
            Optional(CallReference(), 1),
            Optional(CauseInd(), 18),
            Optional(UserToUserInd(), 42),
            Optional(UserToUserInfo(), 32),
            Optional(AccessTransport(), 3),
            Optional(GenericNotifInd(), 44),
            Optional(TransmissionMediumUsed(), 53),
            Optional(EchoControlInfo(), 55),
            Optional(AccessDeliveryInfo(), 46),
            Optional(RedirectionNum(), 12),
            Optional(ParameterCompatInfo(), 57),
            Optional(CallDiversionInfo(), 54),
            Optional(NetworkSpecificFacility(), 47),
            Optional(RemoteOperations(), 50),
            Optional(ServiceActivation(), 51),
            Optional(RedirectNumRestriction(), 64),
            Optional(ConferenceTreatmentInd(), 114),
            Optional(UIDActionInd(), 116),
            Optional(AppTransportParam(), 120),
            Optional(CCNRPossibleInd(), 122),
            Optional(HTRInfo(), 130),
            Optional(PivotRoutingBackwardInfo(), 137),
            Optional(RedirectStatus(), 138),
            Optional(EOO(), 0),
            ))
        )
        

class Answer(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x9, dic=ISUPType_dict),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Opt'),
            )),
        ISUPOpt('Opt', GEN=(
            Optional(BackwardCallInd(), 17),
            Optional(OptBackwardCallInd(), 41),
            Optional(CallReference(), 1),
            Optional(UserToUserInd(), 42),
            Optional(UserToUserInfo(), 32),
            Optional(ConnectedNum(), 33),
            Optional(AccessTransport(), 3),
            Optional(AccessDeliveryInfo(), 46),
            Optional(GenericNotifInd(), 44),
            Optional(ParameterCompatInfo(), 57),
            Optional(BackwardGVNS(), 77),
            Optional(CallHistoryInfo(), 45),
            Optional(GenericNum(), 192),
            Optional(TransmissionMediumUsed(), 53),
            Optional(NetworkSpecificFacility(), 47),
            Optional(RemoteOperations(), 50),
            Optional(RedirectionNum(), 12),
            Optional(ServiceActivation(), 51),
            Optional(EchoControlInfo(), 55),
            Optional(RedirectNumRestriction(), 64),
            Optional(DisplayInfo(), 115),
            Optional(ConferenceTreatmentInd(), 114),
            Optional(AppTransportParam(), 120),
            Optional(PivotRoutingBackwardInfo(), 137),
            Optional(RedirectStatus(), 138),
            Optional(EOO(), 0),
            ))
        )


class CallProgress(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x2c, dic=ISUPType_dict),
        EventInfo(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Opt'),
            )),
        ISUPOpt('Opt', GEN=(
            Optional(CauseInd(), 18),
            Optional(CallReference(), 1),
            Optional(BackwardCallInd(), 17),
            Optional(OptBackwardCallInd(), 41),
            Optional(AccessTransport(), 3),
            Optional(UserToUserInd(), 42),
            Optional(RedirectionNum(), 12),
            Optional(UserToUserInfo(), 32),
            Optional(GenericNotifInd(), 44),
            Optional(NetworkSpecificFacility(), 47),
            Optional(RemoteOperations(), 50),
            Optional(TransmissionMediumUsed(), 53),
            Optional(AccessDeliveryInfo(), 46),
            Optional(ParameterCompatInfo(), 57),
            Optional(CallDiversionInfo(), 54),
            Optional(ServiceActivation(), 51),
            Optional(RedirectNumRestriction(), 64),
            Optional(CallTransferNum(), 69),
            Optional(EchoControlInfo(), 55),
            Optional(ConnectedNum(), 33),
            Optional(BackwardGVNS(), 77),
            Optional(GenericNum(), 192),
            Optional(CallHistoryInfo(), 45),
            Optional(ConferenceTreatmentInd(), 114),
            Optional(UIDActionInd(), 116),
            Optional(AppTransportParam(), 120),
            Optional(CCNRPossibleInd(), 122),
            Optional(PivotRoutingBackwardInfo(), 137),
            Optional(RedirectStatus(), 138),
            Optional(EOO(), 0),
            ))
        )


class CircuitGroupQueryResp(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x2b, dic=ISUPType_dict),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='RangeStatus'),
            Ptr8('Ptr1', field='CircuitStateInd'),
            )),
        Variable(RangeStatus()),
        Variable(CircuitStateInd()),
        )


class CircuitGroupResetAck(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x29, dic=ISUPType_dict),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='RangeStatus'),
            )),
        Variable(RangeStatus()),
        )


class Confusion(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x2f, dic=ISUPType_dict),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='CauseInd'),
            Ptr8('Ptr1', field='Opt'),
            )),
        Variable(CauseInd()),
        ISUPOpt('Opt', GEN=(
            Optional(EOO(), 0),
            ))
        )


class Connect(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x7, dic=ISUPType_dict),
        BackwardCallInd(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Opt'),
            )),
        ISUPOpt('Opt', GEN=(
            Optional(OptBackwardCallInd(), 41),
            Optional(BackwardGVNS(), 77),
            Optional(ConnectedNum(), 33),
            Optional(CallReference(), 1),
            Optional(UserToUserInd(), 42),
            Optional(UserToUserInfo(), 32),
            Optional(AccessTransport(), 3),
            Optional(NetworkSpecificFacility(), 47),
            Optional(GenericNotifInd(), 44),
            Optional(RemoteOperations(), 50),
            Optional(TransmissionMediumUsed(), 53),
            Optional(EchoControlInfo(), 55),
            Optional(AccessDeliveryInfo(), 46),
            Optional(CallHistoryInfo(), 45),
            Optional(ParameterCompatInfo(), 57),
            Optional(ServiceActivation(), 51),
            Optional(GenericNum(), 192),
            Optional(RedirectNumRestriction(), 64),
            Optional(ConferenceTreatmentInd(), 114),
            Optional(AppTransportParam(), 120),
            Optional(HTRInfo(), 130),
            Optional(PivotRoutingBackwardInfo(), 137),
            Optional(RedirectStatus(), 138),
            Optional(EOO(), 0),
            ))
        )


class Continuity(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x5, dic=ISUPType_dict),
        ContinuityInd(),
        )


class FacilityReject(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x21, dic=ISUPType_dict),
        FacilityInd(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='CauseInd'),
            Ptr8('Ptr1', field='Opt'),
            )),
        Variable(CauseInd()),
        ISUPOpt('Opt', GEN=(
            Optional(UserToUserInd(), 42),
            Optional(EOO(), 0),
            ))
        )


class Information(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x4, dic=ISUPType_dict),
        InformationInd(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Opt'),
            )),
        ISUPOpt('Opt', GEN=(
            Optional(CallingPartyCat(), 9),
            Optional(CallingPartyNum(), 10),
            Optional(CallReference(), 1),
            Optional(ConnectionReq(), 13),
            Optional(ParameterCompatInfo(), 57),
            Optional(NetworkSpecificFacility(), 47),
            Optional(EOO(), 0),
            ))
        )


class InformationReq(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x3, dic=ISUPType_dict),
        InformationReqInd(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Opt'),
            )),
        ISUPOpt('Opt', GEN=(
            Optional(CallReference(), 1),
            Optional(NetworkSpecificFacility(), 47),
            Optional(ParameterCompatInfo(), 57),
            Optional(EOO(), 0),
            ))
        )


class InitialAddress(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x1, dic=ISUPType_dict),
        NatureConnectionInd(),
        ForwardCallInd(),
        CallingPartyCat(),
        TransmissionMediumReq(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='CalledPartyNum'),
            Ptr8('Ptr1', field='Opt'),
            )),
        Variable(CalledPartyNum()),
        ISUPOpt('Opt', GEN=(
            Optional(TransitNetworkSel(), 35),
            Optional(CallReference(), 1),
            Optional(CallingPartyNum(), 10),
            Optional(OptForwardCallInd(), 8),
            Optional(RedirectingNum(), 11),
            Optional(RedirectionInfo(), 19),
            Optional(ClosedUserGroupInterlockCode(), 26),
            Optional(ConnectionReq(), 13),
            Optional(OriginalCalledNum(), 40),
            Optional(UserToUserInfo(), 32),
            Optional(AccessTransport(), 3),
            Optional(UserServiceInfo(), 29),
            Optional(UserToUserInd(), 42),
            Optional(GenericNum(), 192),
            Optional(PropagationDelayCounter(), 49),
            Optional(UserServiceInfoPrime(), 48),
            Optional(NetworkSpecificFacility(), 47),
            Optional(GenericDigits(), 193),
            Optional(OriginISCPointCode(), 43),
            Optional(UserTeleserviceInfo(), 52),
            Optional(RemoteOperations(), 50),
            Optional(ParameterCompatInfo(), 57),
            Optional(GenericNotifInd(), 44),
            Optional(ServiceActivation(), 51),
            Optional(MLPPPrecedence(), 58),
            Optional(TransmissionMediumReqPrime(), 62),
            Optional(LocationNum(), 63),
            Optional(ForwardGVNS(), 76),
            Optional(CCSS(), 75),
            Optional(NetworkMgmtControls(), 91),
            Optional(CircuitAssignMap(), 37),
            Optional(CorrelationID(), 101),
            Optional(CallDiversionTreatmentInd(), 110),
            Optional(CalledINNum(), 111),
            Optional(CallOfferingTreatmentInd(), 112),
            Optional(ConferenceTreatmentInd(), 114),
            Optional(ScfID(), 102),
            Optional(UIDCapInd(), 117),
            Optional(EchoControlInfo(), 55),
            Optional(HopCounter(), 61),
            Optional(CollectCallReq(), 121),
            Optional(AppTransportParam(), 120),
            Optional(PivotCap(), 123),
            Optional(CalledDirectoryNum(), 125),
            Optional(OriginalCalledINNum(), 127),
            Optional(CallingGeodeticLocation(), 129),
            Optional(NetworkRoutingNum(), 132),
            Optional(QueryOnReleaseCap(), 133),
            Optional(PivotCounter(), 135),
            Optional(PivotRoutingForwardInfo(), 136),
            Optional(RedirectCap(), 78),
            Optional(RedirectCounter(), 119),
            Optional(RedirectStatus(), 138),
            Optional(RedirectForwardInfo(), 139),
            Optional(NumPortabilityForwardInfo(), 141),
            Optional(EOO(), 0),
            ))
        )


class Release(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0xc, dic=ISUPType_dict),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='CauseInd'),
            Ptr8('Ptr1', field='Opt'),
            )),
        Variable(CauseInd()),
        ISUPOpt('Opt', GEN=(
            Optional(RedirectionInfo(), 19),
            Optional(RedirectionNum(), 12),
            Optional(AccessTransport(), 3),
            Optional(SignallingPointCode(), 30),
            Optional(UserToUserInfo(), 32),
            Optional(AutomaticCongestionLevel(), 39),
            Optional(NetworkSpecificFacility(), 47),
            Optional(AccessDeliveryInfo(), 46),
            Optional(ParameterCompatInfo(), 57),
            Optional(UserToUserInd(), 42),
            Optional(DisplayInfo(), 115),
            Optional(RemoteOperations(), 50),
            Optional(HTRInfo(), 130),
            Optional(RedirectCounter(), 119),
            Optional(RedirectBackwardInfo(), 140),
            Optional(EOO(), 0),
            ))
        )


class ReleaseComplete(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x10, dic=ISUPType_dict),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Opt'),
            )),
        ISUPOpt('Opt', GEN=(
            Optional(CauseInd(), 18),
            Optional(EOO(), 0),
            ))
        )


class SubsequentAddr(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x2, dic=ISUPType_dict),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='SubsequentNum'),
            Ptr8('Ptr1', field='Opt'),
            )),
        Variable(SubsequentNum()),
        ISUPOpt('Opt', GEN=(
            Optional(EOO(), 0),
            ))
        )


class UserToUserInfo(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x2d, dic=ISUPType_dict),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='UserToUserInfo'),
            Ptr8('Ptr1', field='Opt'),
            )),
        Variable(UserToUserInfo()),
        ISUPOpt('Opt', GEN=(
            Optional(AccessTransport(), 3),
            Optional(EOO(), 0),
            ))
        )


class ForwardTransfer(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x8, dic=ISUPType_dict),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Opt'),
            )),
        ISUPOpt('Opt', GEN=(
            Optional(CallReference(), 1),
            Optional(EOO(), 0),
            ))
        )


class Resume(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0xe, dic=ISUPType_dict),
        SuspendResumeInd(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Opt'),
            )),
        ISUPOpt('Opt', GEN=(
            Optional(CallReference(), 1),
            Optional(EOO(), 0),
            ))
        )


class Suspend(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0xd, dic=ISUPType_dict),
        SuspendResumeInd(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Opt'),
            )),
        ISUPOpt('Opt', GEN=(
            Optional(CallReference(), 1),
            Optional(EOO(), 0),
            ))
        )


class Blocking(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x13, dic=ISUPType_dict)
        )


class BlockingAck(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x15, dic=ISUPType_dict)
        )


class ContinuityCheckReq(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x11, dic=ISUPType_dict)
        )


class LoopbackAck(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x24, dic=ISUPType_dict)
        )


class Overload(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x30, dic=ISUPType_dict)
        )


class ResetCircuit(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x12, dic=ISUPType_dict)
        )


class Unblocking(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x14, dic=ISUPType_dict)
        )


class UnblockingAck(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x16, dic=ISUPType_dict)
        )


class UnequippedCIC(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x2e, dic=ISUPType_dict)
        )


class CircuitGroupBlocking(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x18, dic=ISUPType_dict),
        CircuitGroupSupervis(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='RangeStatus'),
            )),
        Variable(RangeStatus()),
        )


class CircuitGroupBlockingAck(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x1a, dic=ISUPType_dict),
        CircuitGroupSupervis(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='RangeStatus'),
            )),
        Variable(RangeStatus()),
        )


class CircuitGroupUnblocking(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x19, dic=ISUPType_dict),
        CircuitGroupSupervis(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='RangeStatus'),
            )),
        Variable(RangeStatus()),
        )


class CircuitGroupUnblockingAck(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x1b, dic=ISUPType_dict),
        CircuitGroupSupervis(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='RangeStatus'),
            )),
        Variable(RangeStatus()),
        )


class CircuitGroupReset(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x17, dic=ISUPType_dict),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='RangeStatus'),
            )),
        Variable(RangeStatus()),
        )


class CircuitGroupQuery(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x2a, dic=ISUPType_dict),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='RangeStatus'),
            )),
        Variable(RangeStatus()),
        )

              
class FacilityAccept(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x20, dic=ISUPType_dict),
        FacilityInd(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Opt'),
            )),
        ISUPOpt('Opt', GEN=(
            Optional(UserToUserInd(), 42),
            Optional(CallReference(), 1),
            Optional(ConnectionReq(), 13),
            Optional(ParameterCompatInfo(), 57),
            Optional(EOO(), 0),
            ))
        )
              
              
class FacilityReq(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x1f, dic=ISUPType_dict),
        FacilityInd(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Opt'),
            )),
        ISUPOpt('Opt', GEN=(
            Optional(UserToUserInd(), 42),
            Optional(CallReference(), 1),
            Optional(ConnectionReq(), 13),
            Optional(ParameterCompatInfo(), 57),
            Optional(EOO(), 0),
            ))
        )


class PassAlong(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x28, dic=ISUPType_dict)
        )


class UserPartTest(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x34, dic=ISUPType_dict),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Opt'),
            )),
        ISUPOpt('Opt', GEN=(
            Optional(ParameterCompatInfo(), 57),
            Optional(EOO(), 0),
            ))
        )


class UserPartAvail(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x35, dic=ISUPType_dict),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Opt'),
            )),
        ISUPOpt('Opt', GEN=(
            Optional(ParameterCompatInfo(), 57),
            Optional(EOO(), 0),
            ))
        )


class Facility(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x33, dic=ISUPType_dict),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Opt'),
            )),
        ISUPOpt('Opt', GEN=(
            Optional(MessageCompatInfo(), 56),
            Optional(ParameterCompatInfo(), 57),
            Optional(RemoteOperations(), 50),
            Optional(ServiceActivation(), 51),
            Optional(CallTransferNum(), 69),
            Optional(AccessTransport(), 3),
            Optional(GenericNotifInd(), 44),
            Optional(RedirectionNum(), 12),
            Optional(PivotRoutingInd(), 124),
            Optional(PivotStatus(), 134),
            Optional(PivotCounter(), 135),
            Optional(PivotRoutingBackwardInfo(), 137),
            Optional(RedirectStatus(), 138),
            Optional(EOO(), 0),
            ))
        )


class NetworkResourceMgmt(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x32, dic=ISUPType_dict),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Opt'),
            )),
        ISUPOpt('Opt', GEN=(
            Optional(MessageCompatInfo(), 56),
            Optional(ParameterCompatInfo(), 57),
            Optional(EchoControlInfo(), 55),
            Optional(EOO(), 0),
            ))
        )


class IdentificationReq(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x36, dic=ISUPType_dict),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Opt'),
            )),
        ISUPOpt('Opt', GEN=(
            Optional(MCIDReqInd(), 59),
            Optional(MessageCompatInfo(), 56),
            Optional(ParameterCompatInfo(), 57),
            Optional(EOO(), 0),
            ))
        )


class IdentificationResp(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x37, dic=ISUPType_dict),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Opt'),
            )),
        ISUPOpt('Opt', GEN=(
            Optional(MCIDRespInd(), 60),
            Optional(MessageCompatInfo(), 56),
            Optional(ParameterCompatInfo(), 57),
            Optional(CallingPartyNum(), 10),
            Optional(AccessTransport(), 3),
            Optional(GenericNum(), 192),
            Optional(ChargedPartyIdent(), 113),
            Optional(EOO(), 0),
            ))
        )


class Segmentation(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x38, dic=ISUPType_dict),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Opt'),
            )),
        ISUPOpt('Opt', GEN=(
            Optional(AccessTransport(), 3),
            Optional(UserToUserInfo(), 32),
            Optional(MessageCompatInfo(), 56),
            Optional(GenericDigits(), 193),
            Optional(GenericNotifInd(), 44),
            Optional(GenericNum(), 192),
            Optional(EOO(), 0),
            ))
        )


class LoopPrevention(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x40, dic=ISUPType_dict),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Opt'),
            )),
        ISUPOpt('Opt', GEN=(
            Optional(MessageCompatInfo(), 56),
            Optional(ParameterCompatInfo(), 57),
            Optional(CallTransferRef(), 67),
            Optional(LoopPreventionInd(), 68),
            Optional(EOO(), 0),
            ))
        )


class ApplicationTransport(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x41, dic=ISUPType_dict),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Opt'),
            )),
        ISUPOpt('Opt', GEN=(
            Optional(MessageCompatInfo(), 56),
            Optional(ParameterCompatInfo(), 57),
            Optional(AppTransportParam(), 120),
            Optional(EOO(), 0),
            ))
        )


class PreReleaseInfo(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x42, dic=ISUPType_dict),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Opt'),
            )),
        ISUPOpt('Opt', GEN=(
            Optional(MessageCompatInfo(), 56),
            Optional(ParameterCompatInfo(), 57),
            Optional(OptForwardCallInd(), 8),
            Optional(OptBackwardCallInd(), 41),
            Optional(AppTransportParam(), 120),
            Optional(EOO(), 0),
            ))
        )


class SubsequentDirectoryNum(ISUPMessage):
    _GEN = (
        Uint16LE('CIC'),
        Uint8('Type', val=0x43, dic=ISUPType_dict),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Opt'),
            )),
        ISUPOpt('Opt', GEN=(
            Optional(SubsequentNum(), 5),
            Optional(MessageCompatInfo(), 56),
            Optional(EOO(), 0),
            ))
        )


#------------------------------------------------------------------------------#
# ISUP Message dispatcher
#------------------------------------------------------------------------------#

ISUPTypeClasses = {
    1  : InitialAddress,
    2  : SubsequentAddr,
    3  : InformationReq,
    4  : Information,
    5  : Continuity,
    6  : AddressComplete,
    7  : Connect,
    8  : ForwardTransfer,
    9  : Answer,
    12 : Release,
    13 : Suspend,
    14 : Resume,
    16 : ReleaseComplete,
    17 : ContinuityCheckReq,
    18 : ResetCircuit,
    19 : Blocking,
    20 : Unblocking,
    21 : BlockingAck,
    22 : UnblockingAck,
    23 : CircuitGroupReset,
    24 : CircuitGroupBlocking,
    25 : CircuitGroupUnblocking,
    26 : CircuitGroupBlockingAck,
    27 : CircuitGroupUnblockingAck,
    31 : FacilityReq,
    32 : FacilityAccept,
    33 : FacilityReject,
    36 : LoopbackAck,
    40 : PassAlong,
    41 : CircuitGroupResetAck,
    42 : CircuitGroupQuery,
    43 : CircuitGroupQueryResp,
    44 : CallProgress,
    45 : UserToUserInfo,
    46 : UnequippedCIC,
    47 : Confusion,
    48 : Overload,
    50 : NetworkResourceMgmt,
    51 : Facility,
    52 : UserPartTest,
    53 : UserPartAvail,
    54 : IdentificationReq,
    55 : IdentificationResp,
    56 : Segmentation,
    64 : LoopPrevention,
    65 : ApplicationTransport,
    66 : PreReleaseInfo,
    67 : SubsequentDirectoryNum,
    }

def get_isup_msg_instances():
    return {k: ISUPTypeClasses[k]() for k in ISUPTypeClasses}


#------------------------------------------------------------------------------#
# SCPP Message parser
#------------------------------------------------------------------------------#

def parse_ISUP(buf):
    """Parses an ISUP message bytes' buffer
    
    Args:
        buf: ISUP message bytes' buffer
    
    Returns:
        element, err: 2-tuple
            element: Element instance, if err is null (no error)
            element: None, if err is not null
            err: 0 no error, 1 invalid message type, 2 message parsing failed
    """
    if len(buf) < 3:
        return None, 1
    if python_version < 3:
        try:
            Msg = ISUPTypeClasses[ord(buf[2])]()
        except:
            return None, 1
    else:
        try:
            Msg = ISUPTypeClasses[buf[2]]()
        except:
            return None, 1
    try:
        Msg.from_bytes(buf)
    except:
        return None, 2
    #
    return Msg, 0


'''
# this is to extract pycrate structure from PDF table from section 4

ISUPType_LUT = {
    0x6  : ('Address complete', AddressComplete),
    0x9  : ('Answer', Answer),
    0x41 : ('Application transport', ApplicationTransport),
    0x13 : ('Blocking', Blocking),
    0x15 : ('Blocking acknowledgement', BlockingAck),
    0x2c : ('Call progress', CallProgress),
    0x18 : ('Circuit group blocking', CircuitGroupBlocking),
    0x1a : ('Circuit group blocking acknowledgement', CircuitGroupBlockingAck),
    0x2a : ('Circuit group query (national use)', CircuitGroupQuery),
    0x2b : ('Circuit group query response (national use)', CircuitGroupQueryResp),
    0x17 : ('Circuit group reset', CircuitGroupReset),
    0x29 : ('Circuit group reset acknowledgement', CircuitGroupResetAck),
    0x19 : ('Circuit group unblocking', CircuitGroupUnblocking),
    0x1b : ('Circuit group unblocking acknowledgement', CircuitGroupUnblockingAck),
#    0x31 : ('Charge information (national use)', None)
    0x2f : ('Confusion', Confusion),
    0x07 : ('Connect', Connect),
    0x05 : ('Continuity', Continuity),
    0x11 : ('Continuity check request', ContinuityCheckReq),
    0x33 : ('Facility', Facility),
    0x20 : ('Facility accepted', FacilityAccept),
    0x21 : ('Facility reject', FacilityReject),
    0x1f : ('Facility request', FacilityReq),
    0x8  : ('Forward transfer', ForwardTransfer),
    0x36 : ('Identification request', IdentificationReq),
    0x37 : ('Identification response', IdentificationResp),
    0x4  : ('Information (national use)', Information),
    0x3  : ('Information request (national use)', InformationReq),
    0x1  : ('Initial address', InitialAddress),
    0x24 : ('Loop back acknowledgement (national use)', LoopbackAck),
    0x40 : ('Loop prevention', LoopPrevention),
    0x32 : ('Network resource management', NetworkResourceMgmt),
    0x30 : ('Overload (national use)', Overload),
    0x28 : ('Pass-along (national use)', PassAlong),
    0x42 : ('Pre-release information', PreReleaseInfo),
    0xc  : ('Release', Release),
    0x10 : ('Release complete', ReleaseComplete),
    0x12 : ('Reset circuit', ResetCircuit),
    0xe  : ('Resume', Resume),
    0x38 : ('Segmentation', Segmentation),
    0x2  : ('Subsequent address', SubsequentAddr),
    0x43 : ('Subsequent Directory Number (national use)', SubsequentDirectoryNum),
    0xd  : ('Suspend', Suspend),
    0x14 : ('Unblocking', Unblocking),
    0x16 : ('Unblocking acknowledgement', UnblockingAck),
    0x2e : ('Unequipped CIC (national use)', UnequippedCIC),
    0x35 : ('User Part available', UserPartAvail),
    0x34 : ('User Part test', UserPartTest),
    0x2d : ('User-to-user information', UserToUserInfo),
    }


ISUPParam_LUT = {
    0x2e : ('Access delivery information', AccessDeliveryInfo),
    0x3  : ('Access transport', AccessTransport),
    0x78 : ('Application transport parameter', AppTransportParam),
    0x27 : ('Automatic congestion level', AutomaticCongestionLevel),
    0x11 : ('Backward call indicators', BackwardCallInd),
    0x4d : ('Backward GVNS', BackwardGVNS),
    0x36 : ('Call diversion information', CallDiversionInfo),
    0x6e : ('Call diversion treatment indicators', CallDiversionTreatmentInd),
    0x2d : ('Call history information', CallHistoryInfo),
    0x70 : ('Call offering treatment indicators', CallOfferingTreatmentInd),
    0x1  : ('Call reference (national use)', CallReference),
    0x45 : ('Call transfer number', CallTransferNum),
    0x43 : ('Call transfer reference', CallTransferRef),
    0x6f : ('Called IN number', CalledINNum),
    0x7d : ('Called directory number (national use)', CalledDirectoryNum),
    0x4  : ('Called party number', CalledPartyNum),
    0x81 : ('Calling geodetic location', CallingGeodeticLocation),
    0xa  : ('Calling party number', CallingPartyNum),
    0x9  : ('Calling party\'s category', CallingPartyCat),
    0x12 : ('Cause indicators', CauseInd),
    0x7a : ('CCNR possible indicator', CCNRPossibleInd),
    0x4b : ('CCSS', CCSS),
    0x71 : ('Charged party identification (national use)', ChargedPartyIdent),
    0x25 : ('Circuit assignment map', CircuitAssignMap),
    0x15 : ('Circuit group supervision message type', CircuitGroupSupervis),
    0x26 : ('Circuit state indicator (national use)', CircuitStateInd),
    0x1a : ('Closed user group interlock code', ClosedUserGroupInterlockCode),
    0x79 : ('Collect call request', CollectCallReq),
    0x72 : ('Conference treatment indicators', ConferenceTreatmentInd),
    0x21 : ('Connected number', ConnectedNum),
    0xd  : ('Connection request', ConnectionReq),
    0x10 : ('Continuity indicators', ContinuityInd),
    0x65 : ('Correlation id', CorrelationID),
    0x73 : ('Display information', DisplayInfo),
    0x37 : ('Echo control information', EchoControlInfo),
    0x0  : ('End of optional parameters', EOO),
    0x24 : ('Event information', EventInfo),
    0x18 : ('Facility indicator', FacilityInd),
    0x7  : ('Forward call indicators', ForwardCallInd),
    0x4c : ('Forward GVNS', ForwardGVNS),
    0xc1 : ('Generic digits (national use)', GenericDigits),
    0x2c : ('Generic notification indicator', GenericNotifInd),
    0xc0 : ('Generic number', GenericNum),
    0x82 : ('HTR information', HTRInfo),
    0x3d : ('Hop counter', HopCounter),
    0xf  : ('Information indicators (national use)', InformationInd),
    0xe  : ('Information request indicators (national use)', InformationReqInd),
    0x3f : ('Location number', LocationNum),
    0x44 : ('Loop prevention indicators', LoopPreventionInd),
    0x3b : ('MCID request indicators', MCIDReqInd),
    0x3c : ('MCID response indicators', MCIDRespInd),
    0x38 : ('Message compatibility information', MessageCompatInfo),
    0x3a : ('MLPP precedence', MLPPPrecedence),
    0x6  : ('Nature of connection indicators', NatureConnectionInd),
    0x5b : ('Network management controls', NetworkMgmtControls),
    0x84 : ('Network routing number (national use)', NetworkRoutingNum),
    0x2f : ('Network specific facility (national use)', NetworkSpecificFacility),
    0x8d : ('Number portability forward information (network option)', NumPortabilityForwardInfo),
    0x29 : ('Optional backward call indicators', OptBackwardCallInd),
    0x8  : ('Optional forward call indicators', OptForwardCallInd),
    0x28 : ('Original called number', OriginalCalledNum),
    0x7f : ('Original called IN number', OriginalCalledINNum),
    0x2b : ('Origination ISC point code', OriginISCPointCode),
    0x39 : ('Parameter compatibility information', ParameterCompatInfo),
    0x7b : ('Pivot capability', PivotCap),
    0x87 : ('Pivot counter', PivotCounter),
    0x89 : ('Pivot routing backward information', PivotRoutingBackwardInfo),
    0x88 : ('Pivot routing forward information', PivotRoutingForwardInfo),
    0x7c : ('Pivot routing indicators', PivotRoutingInd),
    0x86 : ('Pivot status (national use)', PivotStatus),
    0x31 : ('Propagation delay counter', PropagationDelayCounter),
    0x85 : ('Query on release capability (network option)', QueryOnReleaseCap),
    0x16 : ('Range and status', RangeStatus),
    0x8c : ('Redirect backward information (national use)', RedirectBackwardInfo),
    0x4e : ('Redirect capability (national use)', RedirectCap),
    0x77 : ('Redirect counter (national use)', RedirectCounter),
    0x8b : ('Redirect forward information (national use)', RedirectForwardInfo),
    0x8a : ('Redirect status (national use)', RedirectStatus),
    0xb  : ('Redirecting number', RedirectingNum),
    0x13 : ('Redirection information', RedirectionInfo),
    0xc  : ('Redirection number', RedirectionNum),
    0x40 : ('Redirection number restriction', RedirectNumRestriction),
    0x32 : ('Remote operations (national use)', RemoteOperations),
    0x66 : ('SCF id', ScfID),
    0x33 : ('Service activation', ServiceActivation),
    0x1e : ('Signalling point code (national use)', SignallingPointCode),
    0x5  : ('Subsequent number', SubsequentNum),
    0x22 : ('Suspend/Resume indicators', SuspendResumeInd),
    0x23 : ('Transit network selection (national use)', TransitNetworkSel),
    0x2  : ('Transmission medium requirement', TransmissionMediumReq),
    0x3e : ('Transmission medium requirement prime', TransmissionMediumReqPrime),
    0x35 : ('Transmission medium used', TransmissionMediumUsed),
    0x74 : ('UID action indicators', UIDActionInd),
    0x75 : ('UID capability indicators', UIDCapInd),
    0x1d : ('User service information', UserServiceInfo),
    0x30 : ('User service information prime', UserServiceInfoPrime),
    0x34 : ('User teleservice information', UserTeleserviceInfo),
    0x2a : ('User-to-user indicators', UserToUserInd),
    0x20 : ('User-to-user information', UserToUserInfo),
    }


import re
SPLIT = r'[ ]{6,}'

def norm_name(name):
    # dedup spaces and go lower case
    name = re.sub('[ ]{2,}', ' ', name.lower())
    # remove parenthesis
    name = name.split('(')[0].strip()
    #
    return name

def convert_table(text):
    #
    F, V, O = [], [], []
    #
    prmlut = {}
    for k, v in ISUPParam_LUT.items(): 
        prmlut[norm_name(v[0])] = (v[1].__name__, k)
    #
    F.append('Uint16LE(\'CIC\'),')
    for line in text.split('\n'):
        line = line.strip()
        if not line:
            continue
        name, cla, typ, le = re.split(SPLIT, line)
        #print(name, cla, typ, le)
        name = norm_name(name)
        if name == 'message type':
            F.append('Uint8(\'Type\', val=0x, dic=ISUPType_dict),')
        else:
            if typ == 'F':
                F.append('%s(),' % prmlut[name][0])
            elif typ == 'V':
                # variable length
                V.append(prmlut[name][0])
            elif typ == 'O':
                O.append(prmlut[name])
    #
    print('class (ISUPMessage):')
    print('    _GEN = (')
    # fixed
    for p in F:
        print('        %s' % p)
    if not V and not O:
        print('        )')
        return
    # pointers
    print('        Envelope(\'Pointers\', GEN=(')
    for i, p in enumerate(V):
        print('            Ptr8(\'Ptr%i\', field=\'%s\'),' % (i, p))
    if O:
        if not V:
            i = 0
        else:
            i += 1
        print('            Ptr8(\'Ptr%i\', field=\'Opt\'),' % i)
    print('            )),')
    # variable
    for p in V:
        print('        %s(),' % p)
    # options
    if O:
        print('        ISUPOpt(\'Opt\', GEN=(')
        for p in O:
            print('            Optional(%s(), %s),' % p)
        print('            ))')
    print('        )')
    #
    #return F, V, O          
'''
