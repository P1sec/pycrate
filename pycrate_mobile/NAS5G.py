# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2019. Benoit Michau. P1Sec.
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
# * File Name : pycrate_mobile/NAS5G.py
# * Created : 2019-12-02
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from pycrate_core.utils import *

from .TS24501_FGMM  import FGMMTypeClasses, FGMMSecProtNASMessage
from .TS24501_FGSM  import FGSMTypeClasses
from .TS24011_PPSMS import PPSMSCPTypeClasses


def parse_NAS5G(buf, inner=True, sec_hdr=True):
    """Parses a 5G NAS message bytes' buffer
    
    Args:
        buf: 5G NAS message bytes' buffer
        inner: if True, decode NASMessage within security header if possible
                        decode ?
                        
        sec_hdr: if True, handle the 5GMM security header
                 otherwise, just consider the NAS message is in plain text
    
    Returns:
        element, err: 2-tuple
            element: Element instance, if err is null (no error)
            element: None, if err is not null (standard 5G NAS error code)
    """
    try:
        # this corresponds actually only to the layout of the 5GMM header
        pd, shr, typ = unpack('>BBB', buf)
    except Exception:
        # error 111, unspecified protocol error
        return None, 111
    #
    if pd == 146:
        # 5GMM
        if sec_hdr and shdr in (1, 2, 3, 4):
            # 5GMM security protected NAS message
            Msg = FGMMSecProtNASMessage()
            try:
                Msg.from_bytes(buf)
            except Exception:
                # error 96, invalid mandatory info
                return None, 96
            if inner and shdr in (1, 3):
                # parse clear-text NAS message container
                cont, err = parse_NAS5G(Msg[3].get_val(), inner=inner)
                if cont is not None:
                    Msg.replace(Msg[3], cont)
                return Msg, err
            else:
                return Msg, 0
        else:
            # sec hdr == 0 or undefined
            # no security, straight 5GMM message
            try:
                Msg = FGMMTypeClasses[typ]()
            except KeyError:
                # error 97, message type non-existent or not implemented
                return None, 97
    #
    elif pd == 46:
        # 5GSM
        try:
            if python_version < 3:
                typ = ord(buf[3:4])
            else:
                typ = buf[3]
        except:
            # error 111, unspecified protocol error
            return None, 111
        try:
            Msg = FGSMTypeClasses[typ]()
        except KeyError:
            # error 97, message type non-existent or not implemented
            return None, 97
    #
    else:
        # error 97: message type non-existent or not implemented
        return None, 97
    #
    if inner and pd == 146:
        if typ in (65, 76, 79, 94):
            nasc = Msg['NASContainer']
            if not nasc.get_trans():
                # NAS Container present in Msg
                cont, err = parse_NAS5G(nasc[-1].get_val(), inner=inner)
                if err:
                    return Msg, err
                else:
                    nasc.replace(nasc[-1], cont)
        #
        if typ in (65, 79, 103, 104):
            payc = Msg['PayloadContainer']
            if not payc.get_trans():
                # Payload container present in Msg
                # TODO: check if IE decoded properly, then decode each entry into a proper msg
                # 5GSM and SMS at 1st
                pass
    #
    return Msg, 0

'''payload container entries:
    1 : 'N1 SM information',
    2 : 'SMS',
    3 : 'LTE Positioning Protocol message container',
    4 : 'SOR transparent container',
    5 : 'UE policy container',
    6 : 'UE parameters update transparent container',
    7 : 'Location services message container',
    8 : 'CIoT user data container',
'''


