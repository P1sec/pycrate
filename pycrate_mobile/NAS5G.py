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
from .TS24501_UEPOL import FGUEPOLTypeClasses
from .TS24519_TSNAF import FGTSNAFEthPortTypeClasses, FGTSNAFBridgeTypeClasses
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
        pd, shdr, typ = unpack('>BBB', buf[:3])
    except Exception:
        # error 111, unspecified protocol error
        return None, 111
    #
    if pd == 126:
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
    try:
        Msg.from_bytes(buf)
    except Exception:
        # error 96, invalid mandatory info
        return None, 96
    #
    if inner:
        if pd == 126:
            if typ in (65, 76, 79, 94):
                nasc = Msg['NASContainer']
                if not nasc.get_trans():
                    # NAS Container present in Msg
                    Cont, err = parse_NAS5G(nasc[-1].get_val(), inner=inner)
                    if err == 0:
                        nasc.replace(nasc['V'], Cont)
            #
            if typ in (65, 79, 103, 104):
                payct, payc = Msg['PayloadContainerType'], Msg['PayloadContainer']
                if not payct.get_trans() and not payc.get_trans():
                    # Payload container present in Msg
                    conttype, contbuf = payct['V'].get_val(), payc['V'].get_val()
                    Cont, err = parse_PayCont(conttype, contbuf)
                    if err == 0:
                        payc.replace(payc['V'], Cont)
        #
        elif pd == 46:
            if typ in (193, 201, 203, 204):
                ethc = Msg['PortMgmtInfoContainer']
                if not ethc.get_trans():
                    # PortMgmtInfoContainer present in Msg
                    Cont, err = parse_PortMgmtInfoCont(ethc['V'].get_val())
                    if err == 0:
                        ethc.replace(ethc['V'], Cont)
    #
    return Msg, 0


def parse_PayCont(conttype, buf):
    
    if conttype == 1 and len(buf) >= 2:
        # 5GSM
        return parse_NAS5G(buf, inner=True)
    
    elif conttype == 2 and len(buf) >= 2:
        # SMS PP
        pd, typ = unpack('>BB', buf[:2])
        pd &= 0xF
        if pd == 9 and typ in (1, 4, 16):
            Cont = PPSMSCPTypeClasses[typ]()
            try:
                Cont.from_bytes(buf)
            except Exception:
                # error 96, invalid mandatory info
                return None, 96
            else:
                return Cont, 0
        else:
            # error 97, Message type non-existent or not implemented
            return None, 97
    
    elif conttype == 3:
        # LPP, TODO
        pass
    
    elif conttype == 4 and len(buf) >= 17:
        # SOR
        Cont = SORTransContainer()
        try:
            Cont.from_bytes(buf)
        except Exception:
            # error 96, invalid mandatory info
            return None, 96
        else:
            return Cont, 0
    
    elif conttype == 5 and len(buf) >= 2:
        # UE policy
        _, typ = unpack('>BB', buf[:2])
        if 1 <= typ <= 4:
            Cont = FGUEPOLTypeClasses[typ]()
            try:
                Cont.from_bytes(buf)
            except Exception:
                # error 96, invalid mandatory info
                return None, 96
            else:
                return Cont, 0
        else:
            # error 97, Message type non-existent or not implemented
            return None, 97
    
    elif conttype == 6 and len(buf) >= 17:
        # UPU
        Cont = UPUTransContainer()
        try:
            Cont.from_bytes(buf)
        except Exception:
            # error 96, invalid mandatory info
            return None, 96
        else:
            return Cont, 0
    
    elif conttype == 7:
        # LCS, TODO
        pass
    
    elif conttype == 8 and len(buf) >= 1:
        # CIoT
        Cont = CIoTSmallDataContainer()
        try:
            Cont.from_bytes(buf)
        except Exception:
            # error 96, invalid mandatory info
            return None, 96
        else:
            return Cont, 0
    
    elif conttype == 15 and len(buf) >= 1:
        # multi
        Cont = PayloadContainerMult()
        try:
            Cont.from_bytes(buf)
        except Exception:
            # error 96, invalid mandatory info
            return None, 96
        else:
            # parse each entry
            for entry in cont['Entries']:
                e_conttype, e_buf = Cont['Type'].get_val(), Cont['Cont'].get_val()
                e_cont, e_err = parse_NAS5GPayCont(e_conttype, e_buf)
                if e_err == 0:
                    entry.replace(entry['Cont'], e_cont)
    
    # error 96, invalid mandatory info
    return None, 96


def parse_PortMgmtInfoCont(buf):
    try:
        # this corresponds actually only to the layout of the 5GMM header
        typ = unpack('>B', buf[:1])
    except Exception:
        # error 96, invalid mandatory info
        return None, 96
    if 1 <= typ <= 6:
        Cont = FGTSNAFEthPortTypeClasses[typ]()
        try:
            Cont.from_bytes(buf)
        except Exception:
            # error 96, invalid mandatory info
            return None, 96
        else:
            return Cont, 0
    else:
        # error 97, Message type non-existent or not implemented
        return None, 97

