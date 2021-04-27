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
# * File Name : pycrate_corenet/HdlrUENG.py
# * Created : 2020-04-29
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from .utils      import *
from .ProcCNNgap import *
from .ProcCNFGMM import *
from .ProcCNFGSM import *
from .HdlrUESMS  import *


class UEFGMMd(SigStack):
    """UE 5GMM handler within a UENGd instance
    responsible for 5G Mobility Management signalling procedures
    """
    
    TRACK_PROC = True
    
    # reference to the UEd
    UE = None
    # reference to the UENGd
    NG = None
    
    # state: DEREGISTERED (cannot be paged) <-> CONNECTED <-> IDLE
    state = 'DEREGISTERED'
    
    # to bypass the process() server loop with a custom NAS PDU handler
    RX_HOOK = None
    
    # additional time for letting background task happen in priority
    _WAIT_ADD = 0.005
    
    
    #--------------------------------------------------------------------------#
    # FGMM timers
    #--------------------------------------------------------------------------#
    
    # MT Deregistration
    T3522   = 1
    # Registration
    T3550   = 1
    # UE Config Update
    T3555   = 2
    # AKA, SMC
    T3560   = 2
    # Identification
    T3570   = 1
    # NSSAI Auth
    T3575   = 2
    
    
    
    
    def _log(self, logtype, msg):
        self.NG._log(logtype, '[5GMM] %s' % msg)
    
    def __init__(self, ued, uengd):
        self.UE = ued
        self.set_ng(uengd)
        #
        # ready event, used by foreground tasks (network / interpreter initiated)
        self.ready = Event()
        self.ready.set()
        # stack of ongoing 5GMM procedures (i.e. common procedures can be run 
        # within specific procedure)
        self.Proc   = []
        # list of tracked procedures (requires TRACK_PROC = True)
        self._proc  = []
    
    def set_ng(self, uengd):
        self.NG = uengd
    
    def process(self, NasRx):
        """process a NAS 5GMM message (NasRx) sent by the UE,
        and return a list (possibly empty) of NGAP procedure(s) to be sent back 
        to the gNB
        """
        # TODO
        return []
    
    def init_proc(self, ProcClass, encod=None, fgmm_preempt=False):
        """initialize a CN-initiated 5GMM procedure of class `ProcClass' and 
        given encoder(s), and return the procedure
        """
        # TODO
        pass
    
    def clear(self):
        """abort all running procedures
        """
        for Proc in self.Proc[::-1]:
            Proc.abort()
    
    #--------------------------------------------------------------------------#
    # SMC and security-related methods
    #--------------------------------------------------------------------------#
    
    
    
    
    #--------------------------------------------------------------------------#
    # network-initiated method (fg task, to be used from the interpreter)
    #--------------------------------------------------------------------------#
    
    def _net_init_con(self):
        if not self.NG.page_block():
            return False
        # need to wait for potential 5GMM serving / common procedures to happen and end
        sleep(self._WAIT_ADD)
        if not self.ready.wait(10):
            # something is blocking in the serving / common procedures
            return False
        elif not self.NG.connected.is_set():
            # something went wrong during the serving / common procedures
            return False
        else:
            return True
    
    def run_proc(self, ProcClass, **IEs):
        """run a network-initiated procedure ProcClass in the context of the 5GMM stack,
        after setting the given IEs in the NAS message to be sent to the UE
        
        returns a 2-tuple (success, proc)
            success is a bool
            proc is the instance of ProcClass or None
        """
        if ProcClass.Init is None:
            self._log('ERR', 'invalid network-initiated procedure %s' % ProcClass.Name)
            return False, None
        if not self._net_init_con():
            return False, None
        #
        Proc = self.init_proc(ProcClass, encod={ProcClass.Init: IEs}, fgmm_preempt=True)
        try:
            NgapTxProc = Proc.output()
        except Exception:
            self._log('ERR', 'invalid IEs for network-initiated procedure %s' % Proc.Name)
            Proc.abort()
            return False, Proc
        if not self.NG.transmit_ngap_proc(NgapTxProc):
            return False, Proc
        #
        # check if a response is expected
        if not hasattr(Proc, 'TimerValue'):
            return True, Proc
        elif not self.ready.wait(Proc.TimerValue + self._WAIT_ADD):
            # procedure is stuck, will be aborted in the server loop
            # WNG: this means the routine for cleaning NAS procedures in timeout 
            # should be enabled in CorenetServer
            return False, Proc
        #
        # check if a response was received
        if hasattr(Proc, 'UEInfo'):
            return True, Proc
        else:
            return False, Proc




class UEFGSMd(SigStack):
    """UE 5GSM handler within a UENGd instance
    responsible for 5G Session Management signalling procedures
    """
    
    TRACK_PROC = True
    
    # reference to the UEd
    UE = None
    # reference to the UENGd
    NG = None
    
    # to bypass the process() server loop with a custom NAS PDU handler
    RX_HOOK = None
    
    
    def _log(self, logtype, msg):
        self.NG._log(logtype, '[5GSM] %s' % msg)
    
    def __init__(self, ued, uengd):
        self.UE = ued
        self.set_ng(uengd)
        #
        # dict of ongoing 5GSM procedures, indexed by 5GS bearer ID
        self.Proc  = {i: [] for i in range(16)}
        # dict of configured PDU, indexed by 5GS bearer ID
        self.PDU   = {}
        # dict of ongoing 5GSM transactions IEs
        self.Trans = {}
        # list of tracked procedures (requires TRACK_PROC = True)
        self._proc = []
    
    def set_ng(self, uengd):
        self.NG = uengd
    
    def process(self, NasRx, FGMMProc=None):
        """process a NAS 5GSM message (NasRx) sent by the UE,
        and return a list (possibly empty) of NGAP procedure(s) to be sent back 
        to the gNB
        
        FGMMProc [FMMSigProc or None], indicates if the NAS FGSM message is handled in 
        the context of an FGMM procedure 
        """
        # TODO
        return []
    
    
    def init_proc(self, ProcClass, **kw):
        """initialize a CN-initiated 5GSM procedure of class `ProcClass' and 
        given encoder(s), and return the procedure
        """
        # TODO
        pass
    
    def clear(self, ebi=None):
        """abort all running procedures, eventually for a single 5GS Bearer ID
        """
        pass
    
    
    #--------------------------------------------------------------------------#
    # transaction processing
    #--------------------------------------------------------------------------#
    
    def process_trans(self, trans_id):
        """process a 5GSM transaction initiated by the UE, and return a network-initiated
        procedure with IEs configured and None, or None and the 5GSM error code
        """
        pass
    
    
    #--------------------------------------------------------------------------#
    # protocol configuration processing
    #--------------------------------------------------------------------------#
    
    


class UENGd(SigStack):
    """UE NG handler within a CorenetServer instance
    responsible for UE-associated NGAP signalling
    """
    
    # to keep track of all NGAP procedures
    TRACK_PROC = True
    
    # domain
    DOM = '5GS'
    
    # reference to the UEd
    UE  = None
    # reference to the GNBd, SCTP stream id
    GNB = None
    SID = None
    
    # to bypass the process_nas() server loop with a custom NAS PDU handler
    RX_HOOK = None
    
    # for pure NGAP procedure (no NAS trafic, neither PDU-oriented stuff)
    # should we page the UE to run the procedure successfully when UE is idle
    NGAP_FORCE_PAGE = False
    
    #--------------------------------------------------------------------------#
    # global security policy
    #--------------------------------------------------------------------------#
    # this will systematically bypass all auth and smc procedures,
    # NAS MAC and UL count verification in the uplink
    # and setting of the 5GMM security header (and encryption) in the downlink
    SECNAS_DISABLED = False
    #
    # finer grained NAS security checks:
    # True to drop NAS PDU when NAS MAC verification fails
    SECNAS_UL_MAC   = False
    # True to drop NAS PDU when NAS UL count verification fails
    SECNAS_UL_CNT   = False
    # WNG: 5GMM and 5GSM stacks have further control on accepting or not certain
    # NAS message even if security control have failed
    #
    # this will disable the setting of the 5GMM security header (and encryption)
    # in the downlink for given NAS message (by name)
    SECNAS_PDU_NOSEC = set()
    #
    # format of the security context dict self.SEC:
    # self.SEC is a dict of available 5G security contexts indexed by KSI,
    # and current KSI in use
    #
    # when self.SEC['KSI'] is not None, the context is enabled at the NAS level, e.g.
    # self.SEC = {'KSI': 0,
    #             0: {'RAND': b'...', 'RES': b'...', 'AUTN': b'...', 'CK': b'...', 'IK': b'...',
    #                 'SNName': b'...', 'ABBA': b'...', 'RESstar': b'...',
    #                 'Kausf': b'...', 'Kseaf': b'...', 'Kamf': b'...',
    #                 'Knasenc': b'...', 'Knasint': b'...', 
    #                 'UL': 0, 'DL': 0, 'NASEA': 0, 'NASIA': 0,
    #                 'Kgnb': b'...'},
    #             ...,
    #             'POL': {'REG': 0, 'SER': 0, 'DER': 0}}
    # 
    # The POL dict indicates the authentication policy for each procedure
    
    
    #--------------------------------------------------------------------------#
    # NGAPPaging policy
    #--------------------------------------------------------------------------#
    #
    
    #--------------------------------------------------------------------------#
    # NGAPInitialContextSetup policy
    #--------------------------------------------------------------------------#
    # 
    
    #--------------------------------------------------------------------------#
    # NGAPTraceStart policy
    #--------------------------------------------------------------------------#
    # 
    
    
    def _log(self, logtype, msg):
        self.UE._log(logtype, '[UENGd:   %3i] %s' % (self.CtxId, msg))
    
    def __init__(self, ued, gnbd=None, ctx_id=-1, sid=None):
        self.UE  = ued
        self.Server = ued.Server
        self.Config = self.Server.ConfigNG
        #
        # dict of ongoing NGAP procedures (indexed by their procedure code)
        self.Proc = {}
        # list of tracked procedures (requires TRACK_PROC = True)
        self._proc = []
        #
        # dict of available 5G security contexts, indexed by KSI
        # and current KSI in use
        self.SEC = {}
        self.reset_sec_ctx()
        #
        self.connected = Event()
        self.nasinit   = Event() # state for initial NAS message 
        if gnbd is not None:
            self.set_ran(gnbd)
        else:
            self.CtxId = -1
        #
        # init 5GMM and 5GSM sig stacks
        self.FGMM = UEFGMMd(ued, self)
        self.FGSM = UEFGSMd(ued, self)
        self.SMS  = UESMSd(ued, self)
    
    def set_ran(self, gnbd):
        self.SEC['KSI'] = None
        self.GNB = gnbd
        self.connected.set()
        self.nasinit.set()
    
    def unset_ran(self):
        self.GNB.unset_ue_ng(self.CtxId)
        del self.GNB
        self.SEC['KSI'] = None
        self.clear()
        self.connected.clear()
        self.nasinit.clear()
    
    def set_ran_unconnected(self, gnbd):
        # required for paging
        self.SEC['KSI'] = None
        self.GNB = gnbd
    
    def unset_ran_unconnected(self):
        # required for paging
        del self.GNB
        self.SEC['KSI'] = None
    
    def is_connected(self):
        return self.connected.is_set()
    
    def set_ctx(self, ctx_id, sid):
        self.CtxId = ctx_id
        self.SID   = sid
    
    def unset_ctx(self):
        self.CtxId = -1
        del self.SID
    
    def reset_sec_ctx(self):
        self.SEC.clear()
        self.SEC['KSI'] = None
        self.SEC['POL'] = {'REG': 0, 'DET': 0, 'SER': 0}
        if 'UESecCap' in self.UE.Cap:
            del self.UE.Cap['UESecCap']
    
    def get_sec_ctx(self):
        return self.SEC.get(self.SEC['KSI'], None)
    
    #--------------------------------------------------------------------------#
    # handling of NGAP procedures
    #--------------------------------------------------------------------------#
    
    def process_ngap_pdu(self, pdu_rx):
        """process a NGAP PDU sent by the gNB for UE-associated signalling
        and return a list of NGAP PDU(s) to be sent back to it
        """
        errcause = None
        if pdu_rx[0] == 'initiatingMessage':
            # gNB-initiated procedure, instantiate it
            try:
                Proc = NGAPProcRANDispatcher[pdu_rx[1]['procedureCode']](self)
            except Exception:
                self._log('ERR', 'invalid NGAP PDU, initiatingMessage, code %i'\
                          % pdu_rx[1]['procedureCode'])
                errcause = ('protocol', 'abstract-syntax-error-reject')
                Proc = self.init_ngap_proc(NGAPErrorIndCN, Cause=errcause)
                if not Proc:
                    return []
            else:
                if self.TRACK_PROC:
                    self._proc.append( Proc )
            # process the PDU within the procedure
            Proc.recv( pdu_rx )
            if Proc.Class == 2 and Proc.errcause:
                Err = self.init_ngap_proc(NGAPErrorIndCN, Cause=Proc.errcause)
                if not Err:
                    return []
                self.ProcLast = Err.Code
                return Err.send()
            elif Proc.Class == 1 or errcause:
                self.ProcLast = Proc.Code
                return Proc.send()
            else:
                pdu_tx = []
                for ProcRet in Proc.trigger():
                    pdu_tx.extend( ProcRet.send() )
                    self.ProcLast = ProcRet.Code
                return pdu_tx
        #
        else:
            # CN-initiated procedure, transfer the PDU to it
            try:
                Proc = self.Proc[pdu_rx[1]['procedureCode']]
            except Exception:
                self._log('ERR', 'invalid NGAP PDU, %s, code %i'\
                          % (pdu_rx[0], pdu_rx[1]['procedureCode']))
                errcause = ('protocol', 'message-not-compatible-with-receiver-state')
                Proc = self.init_ngap_proc(NGAPErrorIndCN, Cause=errcause)
                if not Proc:
                    return []
            # process the PDU within the procedure
            Proc.recv( pdu_rx )
            if Proc.errcause:
                Err = self.init_ngap_proc(NGAPErrorIndCN, Cause=Proc.errcause)
                if not Err:
                    return []
                self.ProcLast = Err.Code
                return Err.send()
            elif errcause:
                self.ProcLast = Proc.Code
                return Proc.send()
            else:
                pdu_tx = []
                for ProcRet in Proc.trigger():
                    pdu_tx.extend( ProcRet.send() )
                    self.ProcLast = ProcRet.Code
                return pdu_tx
    
    def init_ngap_proc(self, ProcClass, **IEs):
        """initialize a CN-initiated NGAP procedure of class `ProcClass' for 
        UE-associated signalling, encode the initiatingMessage PDU with given 
        **IEs and return the procedure
        """
        Proc = self._init_ngap_proc(ProcClass)
        if not Proc:
            return None
        else:
            self._encode_ngap_proc(Proc, **IEs)
            return Proc
    
    def _init_ngap_proc(self, ProcClass):
        if not issubclass(ProcClass, NGAPSigProc):
            self._log('WNG', 'starting an invalid procedure for UE-associated NG signalling')
        if ProcClass.Code in self.Proc:
            self._log('ERR', 'an NGAP procedure %s is already ongoing' % ProcClass.__name__)
            return None
        try:
            Proc = ProcClass(self)
        except Exception:
            # no active NG link
            self._log('ERR', 'no active NG link to initialize the NGAP procedure %s'\
                      % ProcClass.__name__)
            return None
        if Proc.Code in NGAPProcCNDispatcher and Proc.Class == 1:
            # store the procedure, which requires a response from the gNB
            self.Proc[Proc.Code] = Proc
        if self.TRACK_PROC:
            self._proc.append( Proc )
        return Proc
    
    def _encode_ngap_proc(self, Proc, **IEs):
        if Proc.Name != 'NGAPUEContextRelease':
            IEs['AMF_UE_NGAP_ID'], IEs['RAN_UE_NGAP_ID'] = self.CtxId, self.CtxId
        else:
            IEs['UE_NGAP_IDs'] = ('uE-NGAP-ID-pair', {'aMF-UE-NGAP-ID': self.CtxId,
                                                      'rAN-UE-NGAP-ID': self.CtxId})
        Proc.encode_pdu('ini', **IEs)
    
    def start_ngap_proc(self, ProcClass, **IEs):
        """initialize a CN-initiated NGAP procedure of class `ProcClass' for 
        UE-associated signalling, encode the initiatingMessage PDU with given 
        **IEs and send the PDU generated by the procedure to the gNB
        """
        if not self.is_connected():
            self._log('ERR', 'not connected')
            return 0
        Proc = self.init_ngap_proc(ProcClass, **IEs)
        if Proc is None:
            return 0
        self.ProcLast, cnt = Proc.Code, 0
        for pdu_tx in Proc.send():
            if self.UE.Server.send_ngap_pdu(self.GNB, pdu_tx, self.SID):
                cnt += 1
        return cnt
    
    def transmit_ngap_proc(self, NgapTxProc):
        """send the NGAP PDU as returned by the .send() method of the NGAP procedures
        in the NgapTxProc list to the gNB
        """
        cnt = 0
        for Proc in NgapTxProc:
            self.ProcLast = Proc.Code
            for pdu_tx in Proc.send():
                if self.UE.Server.send_ngap_pdu(self.GNB, pdu_tx, self.SID):
                    cnt += 1
        return cnt
    
    def clear(self):
        # clears all running NGAP procedures
        for Proc in list(self.Proc.values()):
            Proc.abort()
    
    #--------------------------------------------------------------------------#
    # handling of NAS messages dispatching
    #--------------------------------------------------------------------------#
    
    def process_nas(self, buf):
        """process a NAS message buffer for the 5GS domain sent by the mobile
        and return a list (possibly empty) of NGAP procedure(s) to be sent back 
        to the gNB
        """
        if self.RX_HOOK:
            return self.RX_HOOK(buf)
        NasRxSec, err = NAS.parse_NAS5G(buf, inner=False)
        if err:
            self._log('WNG', 'invalid 5GS NAS message: %s' % hexlify(buf).decode('ascii'))
            return self.ret_ngap_dnt(NAS.FGMMStatus(val={'5GMMCause':err}, sec=False))
        #
        # 5GS NAS security handling
        
        
        sh, pd = NasRxSec[0]['SecHdr'].get_val(), NasRxSec[0]['EPD'].get_val()
        if sh == 0:
            # clear-text NAS message
            NasRxSec._sec   = False
            NasRxSec._ulcnt = 0
            if self.UE.TRACE_NAS_5GS:
                self._log('TRACE_NAS_5GS_UL', '\n' + NasRxSec.show())
            if pd == 126:
                NgapTxProc = self.FGMM.process(NasRxSec)
            else:
                assert( pd == 46 ) # this won't happen due to parse_NAS5G()
                NgapTxProc = self.FGSM.process(NasRxSec)
        elif sh in (2, 4) and pd == 126:
            if self.UE.TRACE_NAS_5GS_SEC:
                self._log('TRACE_NAS_5GS_UL_SEC', '\n' + NasRxSec.show())
            NasRx, err = self.process_nas_sec_enc(NasRxSec, sh)
            if err & 0xff:
                # non-security related error
                NgapTxProc = self.ret_ngap_dnt(NAS.FGMMStatus(val={'5GMMCause': err}, sec=True))
            elif not NasRx:
                # deciphering failed
                return self._ngap_nas_sec_err()
            else:
                if self.UE.TRACE_NAS_5GS:
                    self._log('TRACE_NAS_5GS_UL', '\n' + NasRx.show())
                if NasRx[0]['EPD'].get_val() == 126:
                    NgapTxProc = self.FGMM.process(NasRx)
                else:
                    NgapTxProc = self.FGSM.process(NasRx)
        else:
            self._log('WNG', 'invalid 5GS NAS message: %r' % NasRxSec)
            NgapTxProc = self.ret_ngap_dnt(NAS.EMMStatus(val={'5GMMCause': 96}, sec=False))
        #
        return NgapTxProc
    
    def process_nas_sec_mac(self, NasRxSec, secctx):
        #
        sqnmsb, sqnlsb = secctx['UL'] & 0xffffff00, secctx['UL'] & 0xff
        verif_mac = NasRxSec.mac_verify(secctx['Knasint'], 0, secctx['EIA'], sqnmsb)
        ue_sqn    = NasRxSec['Seqn'].get_val()
        verif_sqn = True if ue_sqn == sqnlsb else False
        #
        if not verif_mac:
            if self.SECNAS_UL_MAC:
                self._log('ERR', 'NAS SEC UL: MAC verif failed, dropping %s' % NasRxSec._name)
                return False, 0x200, False, 0
            else:
                self._log('WNG', 'NAS SEC UL: MAC verif failed in %s' % NasRxSec._name)
                return True, 0x200, False, sqnmsb+ue_sqn
        elif not verif_sqn:
            if self.SECNAS_UL_CNT:
                self._log('ERR', 'NAS SEC UL: UL count verif failed, dropping %s' % NasRxSec._name)
                return False, 0x300, False, 0
            else:
                self._log('WNG', 'NAS SEC UL: UL count verif failed in %s' % NasRxSec._name)
                # resynch uplink count
                secctx['UL'] = sqnmsb+ue_sqn+1
                return True, 0x300, False, sqnmsb+ue_sqn
        else:
            self._log('DBG', 'NAS SEC UL: MAC verified, UL count %i' % secctx['UL'])
            ulcnt = secctx['UL']
            secctx['UL'] += 1
            return True, 0, True, ulcnt
    
    def process_nas_sec_enc(self, NasRxSec, sh):
        """Check the security on all UL 5GMM messages which are encrypted.
        Returns the message or None (if security checks are enforced), and the
        security error code.
        
        Security error codes:
        0: no error
        0x100: no active NAS KSI
        0x200: MAC verification failed
        0x300: NAS UL count not matching
        
        The returned message gets 2 attributes (_sec [bool], _ulcnt [uint])
        """
        if self.SECNAS_DISABLED:
            # TODO: try to decode the inner NAS message, in case 5G-EA0 is in use ?
            self._log('WNG', 'unable to decode the inner NAS message')
            return None, 0
        #
        if self.SEC['KSI'] not in self.SEC:
            # no active KSI: happens when restarting corenet, and UE using a forgotten sec ctx
            self._log('WNG', 'NAS SEC UL: no active NAS KSI')
            return None, 0x100
        else:
            secctx = self.SEC[self.SEC['KSI']]
        #
        chk, err, sec, ulcnt = self.process_nas_sec_mac(NasRxSec, secctx)
        if not chk:
            return None, err
        #
        if secctx['NASEA'] == 0:
            buf = NasRxSec['NASMessage'].get_val()
        else:
            NasRxSec.decrypt(secctx['Knasenc'], 0, secctx['NASEA'], ulcnt & 0xffffff00, 1)
            buf = NasRxSec._dec_msg
        NasRx, err2 = NAS.parse_NAS5G(buf, inner=False)
        if err2:
            # decrypted decoded part is malformed
            self._log('WNG', 'invalid 5GS NAS message: %s' % hexlify(buf).decode('ascii'))
        NasRx._sec   = sec
        NasRx._ulcnt = ulcnt
        return NasRx, err + err2
    
    def output_nas_sec(self, NasTx):
        """Apply the security on all DL 5GSM / 5GMM messages.
        Returns the encoded bytes buffer or None if error.
        """
        # TODO
        pass
    
    
    
    def ret_ngap_dnt(self, NasTx, **IEs):
        """returns an NGAPDownlinkNASTransport procedure initialized with the 
        NAS PDU and optional IEs to be sent
        """
        if not NasTx:
            return []
        else:
            buf = self.output_nas_sec(NasTx)
            if buf is None:
                return self._ngap_nas_sec_err()
            IEs['NAS_PDU'] = buf
            S1apProc = self.init_s1ap_proc(S1APDownlinkNASTransport, **IEs)
            if S1apProc:
                return [S1apProc]
            else:
                return []
    
    def _ngap_nas_sec_err(self):
        # TODO: maybe release the NG-UE link ?
        return []
    
    def clear_nas_proc(self):
        # clears all NAS EPS procedures
        self.FGMM.clear()
        self.FGSM.clear()
        self.SMS.clear()
    
    #--------------------------------------------------------------------------#
    # network-initiated method (fg task, to be used from the interpreter)
    #--------------------------------------------------------------------------#
    
    
    
    
    #--------------------------------------------------------------------------#
    # to send arbitrary NAS buffers to the UE
    #--------------------------------------------------------------------------#
    
    
    
    
    #--------------------------------------------------------------------------#
    # 5G bearer activation
    #--------------------------------------------------------------------------#
    

