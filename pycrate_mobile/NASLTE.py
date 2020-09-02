# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2017. Benoit Michau. ANSSI.
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
# * File Name : pycrate_mobile/NASLTE.py
# * Created : 2017-11-08
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from pycrate_core.utils import *

from .TS24301_EMM   import EMMTypeMOClasses, EMMTypeMTClasses, \
                           EMMSecProtNASMessage, EMMServiceRequest
from .TS24301_ESM   import ESMTypeClasses
from .TS24011_PPSMS import PPSMSCPTypeClasses


def parse_NASLTE_MO(buf, inner=True, sec_hdr=True):
    """Parses a Mobile Originated LTE NAS message bytes' buffer
    
    Args:
        buf: uplink LTE NAS message bytes' buffer
        inner: if True, decode NASMessage within security header if possible
                        decode ESMContainer within EMM message if possible
                        decode NASContainer within EMM NAS Transport message if possible
        sec_hdr: if True, handle the NAS EMM security header
                 otherwise, just consider the NAS message is in plain text
    
    Returns:
        element, err: 2-tuple
            element: Element instance, if err is null (no error)
            element: None, if err is not null (standard LTE NAS error code)
    """
    if python_version < 3:
        try:
            pd = ord(buf[:1])
        except Exception:
            # error 111, unspecified protocol error
            return None, 111
    else:
        try:
            pd = buf[0]
        except Exception:
            return None, 111
    shdr = pd>>4
    pd  &= 0xf
        
    if sec_hdr and shdr in (1, 2, 3, 4):
        # EMM security protected NAS message
        Msg = EMMSecProtNASMessage()
        try:
            Msg.from_bytes(buf)
        except Exception:
            # error 96, invalid mandatory info
            return None, 96
        #
        if inner and shdr in (1, 3):
            # parse clear-text NAS message container
            cont, err = parse_NASLTE_MO(Msg[3].get_val(), inner=inner)
            if cont is not None:
                Msg.replace(Msg[3], cont)
            return Msg, err
        else:
            return Msg, 0
        
    elif sec_hdr and shdr == 12:
        # EMM service request message
        Msg = EMMServiceRequest()
        try:
            Msg.from_bytes(buf)
        except Exception:
            return None, 96
        return Msg, 0
    
    else:
        # sec hdr == 0 or undefined
        # no security, straight LTE NAS message
        #
        if pd == 7:
            # EMM
            if python_version < 3:
                try:
                    typ = ord(buf[1:2])
                except Exception:
                    return None, 111
            else:
                try:
                    typ = buf[1]
                except Exception:
                    return None, 111
            try:
                Msg = EMMTypeMOClasses[typ]()
            except KeyError:
                # error 97, message type non-existent or not implemented
                return None, 97
        elif pd == 2:
            # ESM
            if python_version < 3:
                try:
                    typ = ord(buf[2:3])
                except Exception:
                    return None, 111
            else:
                try:
                    typ = buf[2]
                except Exception:
                    return None, 111
            try:
                Msg = ESMTypeClasses[typ]()
            except KeyError:
                return None, 97
        else:
            return None, 97
        #
        try:
            Msg.from_bytes(buf)
        except Exception:
            # error 96, invalid mandatory info
            return None, 96
        #
        if inner and pd == 7:
            if typ in (65, 66, 67, 68, 77):
                esmc = Msg['ESMContainer']
                if not esmc.get_trans():
                    # ESM Container present in Msg
                    cont, err = parse_NASLTE_MO(esmc[-1].get_val(), inner=inner)
                    if err:
                        return Msg, err
                    else:
                        esmc.replace(esmc[-1], cont)
            elif typ in (98, 99):
                # PP-SMS
                nasc   = Msg['NASContainer']
                ppsmsb = nasc[1].get_val()
                try:
                    pd, typ = unpack('>BB', ppsmsb[:2])
                except Exception:
                    return Msg, 111
                pd &= 0xF
                if pd == 9 and typ in (1, 4, 16):
                    cont = PPSMSCPTypeClasses[typ]()
                    try:
                        cont.from_bytes(ppsmsb)
                    except Exception:
                        return Msg, 96
                    nasc.replace(nasc[1], cont)
        #
        return Msg, 0


def parse_NASLTE_MT(buf, inner=True, sec_hdr=True):
    """Parses a Mobile Terminated LTE NAS message bytes' buffer
    
    Args:
        buf: downlink LTE NAS message bytes' buffer
        inner: if True, decode NASMessage within security header if possible
                        decode ESMContainer within EMM message if possible
                        decode NASContainer within EMM NAS Transport message if possible
        sec_hdr: if True, handle the NAS EMM security header
                 otherwise, just consider the NAS message is in plain text
    
    Returns:
        element, err: 2-tuple
            element: Element instance, if err is null (no error)
            element: None, if err is not null (standard LTE NAS error code)
    """
    if python_version < 3:
        try:
            pd = ord(buf[0])
        except Exception:
            # error 111, unspecified protocol error
            return None, 111
    else:
        try:
            pd = buf[0]
        except Exception:
            return None, 111
    shdr = pd>>4
    pd  &= 0xf
        
    if sec_hdr and shdr in (1, 2, 3, 4):
        # EMM security protected NAS message
        Msg = EMMSecProtNASMessage()
        try:
            Msg.from_bytes(buf)
        except Exception:
            # error 96, invalid mandatory info
            return None, 96
        #
        if inner and shdr in (1, 3):
            # parse clear-text NAS message container
            cont, err = parse_NASLTE_MT(Msg[3].get_val(), inner=inner)
            if cont is not None:
                Msg.replace(Msg[3], cont)
            return Msg, err
        else:
            return Msg, 0
        
    elif sec_hdr and shdr == 12:
        # EMM service request message
        Msg = EMMServiceRequest()
        try:
            Msg.from_bytes(buf)
        except Exception:
            return None, 96
        return Msg, 0
    
    else:
        # sec hdr == 0 or undefined
        # no security, straight LTE NAS message
        #
        if pd == 7:
            # EMM
            if python_version < 3:
                try:
                    typ = ord(buf[1])
                except Exception:
                    return None, 111
            else:
                try:
                    typ = buf[1]
                except Exception:
                    return None, 111
            try:
                Msg = EMMTypeMTClasses[typ]()
            except KeyError:
                # error 97, message type non-existent or not implemented
                return None, 97
        elif pd == 2:
            # ESM
            if python_version < 3:
                try:
                    typ = ord(buf[2])
                except Exception:
                    return None, 111
            else:
                try:
                    typ = buf[2]
                except Exception:
                    return None, 111
            try:
                Msg = ESMTypeClasses[typ]()
            except KeyError:
                return None, 97
        else:
            return None, 97
        #
        try:
            Msg.from_bytes(buf)
        except Exception:
            # error 96, invalid mandatory info
            return None, 96
        #
        if inner and pd == 7:
            if typ in (65, 66, 67, 68, 77):
                # ESM Container
                esmc = Msg['ESMContainer']
                if not esmc.get_trans():
                    # ESM Container present in Msg
                    cont, err = parse_NASLTE_MO(esmc[-1].get_val(), inner=inner)
                    if err:
                        return Msg, err
                    else:
                        esmc.replace(esmc[-1], cont)
                        #esmc[-2].set_valauto(cont.get_len)
            elif typ in (98, 99):
                # PP-SMS
                nasc   = Msg['NASContainer']
                ppsmsb = nasc[1].get_val()
                try:
                    pd, typ = unpack('>BB', ppsmsb[:2])
                except Exception:
                    return Msg, 111
                pd &= 0xF
                if pd == 9 and typ in (1, 4, 16):
                    cont = PPSMSCPTypeClasses[typ]()
                    try:
                        cont.from_bytes(ppsmsb)
                    except Exception:
                        return Msg, 96
                    nasc.replace(nasc[1], cont)
        #
        return Msg, 0

# TODO: handle decoding of NAS Generic Container (for LCS or LPP)
# see 24.301, 9.9.3.42 and 43
