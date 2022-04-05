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

from pycrate_mobile.TS24501_IE      import (
    FGSIDTYPE_NO, # 0
    FGSIDTYPE_SUPI,
    FGSIDTYPE_GUTI,
    FGSIDTYPE_IMEI,
    FGSIDTYPE_STMSI,
    FGSIDTYPE_IMEISV,
    FGSIDTYPE_MAC,
    FGSIDTYPE_EUI64, # 7
    FGSIDFMT_IMSI, # 0
    FGSIDFMT_NSI,
    FGSIDFMT_GCI,
    FGSIDFMT_GLI, # 3
    UESecCap as FGSUESecCap
    )


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
    # FGMMAuthentication policy
    #--------------------------------------------------------------------------#
    # this will systematically bypass all authentication procedures
    AUTH_DISABLED       = False
    # 5GMM procedure timer for auth and smc
    T3560               = 2
    # Authentication Management Field
    AUTH_AMF            = b'\x80\x00'
    # Authentication ABBA
    AUTH_ABBA           = b'\x00\x00'
    # if AUTH_PLMN is not None, it will be used for building the 5G auth vector
    # otherwise the main Corenet PLMN will be used
    AUTH_PLMN           = None
    # this is to force a 2G or 3G authentication instead of a 5G one
    AUTH_2G             = False
    AUTH_3G             = False
    # this is to extend AUTN with arbitrary data
    AUTH_AUTN_EXT       = None
    #
    # re-authentication policy:
    # this forces an auth procedure every X 5GMM Reg / Service / Detach procedures 
    # even if a valid KSI is provided by the UE
    AUTH_REG            = 1
    AUTH_SER            = 3
    AUTH_DET            = 1 # only applied to Detach without UE power off
    
    
    
    
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
    
    def require_auth(self, Proc, ksi=None):
        return True
    
    def require_smc(self, Proc):
        return True
    
    def get_new_ksi(self):
        for i in range(0, 7):
            if i not in self.NG.SEC:
                return i
        # all native KSI have been used, clear all of them except the current one
        # if defined
        cur = self.NG.SEC['KSI']
        for i in range(0, 7):
            if i != cur:
                del self.NG.SEC[i]
        if cur == 0:
            return 1
        else:
            return 0
    
    def set_sec_ctx(self, ksi, ctx, vect, snid):
        ksi = (ksi[0]<<3) + ksi[1]
        if ctx == 2:
            # WNG: this is undefined / illegal and won't work (hopefully)
            CK, IK = conv_102_C4(vect[2]), conv_102_C5(vect[2])
            if self.AUTH_PLMN:
                snid = make_5g_snn(self.AUTH_PLMN)
            else:
                snid = make_5g_snn(self.UE.Server.PLMN)
            Kausf    = conv_501_A2(CK, IK, sn_name, sqnak)
            secctx = {'VEC'  : vect,
                      'CTX'  : ctx,
                      'Kc'   : vect[2],
                      'CK'   : CK,
                      'IK'   : IK,
                      'Kausf': Kausf}
        elif ctx == 3:
            # WNG: this is also undefined and shouldn't work
            if self.AUTH_PLMN:
                snid = make_5g_snn(self.FGMM.AUTH_PLMN)
            else:
                snid = make_5g_snn(self.UE.Server.PLMN)
            Kausf  = conv_(vect[3], vect[4], snid, vect[2][:6])
            secctx = {'VEC'  : vect,
                      'CTX'  : ctx,
                      'CK'   : vect[3],
                      'IK'   : vect[4],
                      'Kausf': Kausf}
        else:
            # ctx == 5
            secctx = {'VEC'  : vect,
                      'CTX'  : ctx,
                      'Kausf': vect[3]}
        #
        secctx['Kseaf'] = conv_501_A6(kausf, snid)
        secctx['Kamf']  = conv_501_A7(kseaf, self.UE.IMSI, self.AUTH_ABBA)
        secctx['UL'], secctx['DL'] = 0, 0
        # TODO: check if a custom UL counter is still required for gNB key derivation
        #secctx['UL_gnb'] = 0
        self.NG.SEC[ksi] = secctx
        self.NG.SEC['KSI'] = ksi
    
    
    #--------------------------------------------------------------------------#
    # network-initiated method (fg task, to be used from the interpreter)
    #--------------------------------------------------------------------------#
    
    def _net_init_con(self):
        if not self.NG.page_block():
            return False
        # need to wait for potential 5GMM serving / common procedures to happen and end
        sleep(self._WAIT_ADD)
        if not self.ready.wait(5):
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
    #
    # 1) NAS Rx path
    #
    # IEs allowed in clear-text initial NAS messages
    SECNAS_RX_CT_IES = {
        # Registration Req
        65 : {
            'NAS_KSI',
            '5GSRegType',
            '5GSID', # needs to be a temp id or SUCI
            'UESecCap',
            'UEStatus',
            'AddGUTI',
            'EPSNASContainer',
            'NASContainer',
            },
        # Service Req
        76 : {
            'ServiceType',
            'NAS_KSI',
            '5GSID', # needs to be a temp id
            'NASContainer',
            },
        # Ctrl Plane Service Req
        79 : {
            'NAS_KSI',
            'CtrlPlaneServiceType',
            'NASContainer',
            }
        }
    #
    # Identity type allowed in clear-text IdentityResponse
    SECNAS_RX_CT_IDTYPE = {
        FGSIDTYPE_NO,
        FGSIDTYPE_SUPI,
        #FGSIDTYPE_GUTI,
        #FGSIDTYPE_STMSI
        }
    #
    # dropping invalid Rx message is the default behaviour
    SECNAS_RX_DROP_INVAL = True
    
    '''
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
    '''
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
    # page_block() parameters:
    # number of retries when not successful
    PAG_RETR = 2
    # timer in sec between retries
    PAG_WAIT = 2
    
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
        # state for NG / radio connection: set with InitialUEMessage, unset with UEContextRelease
        self.connected = Event()
        # state for processing the initial NAS message: unset after InitialUEMessage processed
        self.nasinit   = Event()
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
            return self.ret_ngap_dnt(NAS.FGMMStatus(val={'5GMMCause': err}, sec=False))
        #
        # 5GS NAS security handling
        sh, pd = NasRxSec[0]['SecHdr'].get_val(), NasRxSec[0]['EPD'].get_val()
        if sh == 0:
            # clear-text NAS message
            if self.UE.TRACE_NAS_5GS:
                self._log('TRACE_NAS_5GS_UL', '\n' + NasRxSec.show())
            if pd == 126:
                return self.process_nas_nosec(NasRxSec)
        #
        elif pd == 126 and sh in (1, 2, 4):
            # protected NAS message
            # 1: integrity prot only, 2: current sec ctx, 4: new sec ctx (SMC after fresh auth)
            return self.process_nas_sec(NasRxSec)
        #
        # invalid NAS message
        self._log('WNG', 'invalid 5GS NAS message security status')
        if self.UE.TRACE_NAS_5GS:
            self._log('TRACE_NAS_5GS_UL', '\n' + NasRxSec.show())
        # err cause 98: Message type not compatible with the protocol state
        return self.ret_ngap_dnt(NAS.FGMMStatus(val={'5GMMCause': 98}, sec=False))
    
    def process_nas_nosec(self, NasRx):
        # Check if the message type is valid or not, log it and eventually drop it
        typ = NasRx[0]['Type'].get_val()
        #
        if typ in (65, 76, 79):
            # initial NAS message
            ct_ies, vln_ies = self.SECNAS_RX_CT_IES[typ], []
            for ie in list(NasRx)[1:]:
                if ie._name not in ct_ies:
                    vln_ies.append(ie._name)
            if vln_ies:
                self._log('VLN', 'unprotected IEs in initial NAS message: %s' % ', '.join(vln_ies))
        #
        elif typ == 92:
            # ident resp
            ie = NasRx['5GSID']['V'].get_val_d()
            if isinstance(ie, dict) and ie['Type'] not in self.SECNAS_RX_CT_IDTYPE:
                self._log('VLN', 'unprotected UE Identity: %r' % ie)
        #
        elif typ not in {69, 70, 87, 89, 95, 100}:
             # not dereg req, dereg acc, auth resp, auth fail, sec mode rej, status
             self._log('VLN', 'invalid unprotected NAS message: %s' % NasRx._name)
             if self.SECNAS_RX_DROP_INVAL:
                return []
        #
        return self.dispatch_nas(NasRx)
    
    def process_nas_sec(self, NasRx):
        # get the KSI and sec ctx
        # verify MAC
        # decrypt
        #
        # in case of MAC only (no encr), we need to go through process_nas_nosec()
        # whatever result of the MAC check
        
        if self.SEC['KSI'] in self.SEC:
            sec_ctx = self.SEC[self.SEC['KSI']]
            if self.SEC['KSI'] is not None:
                self.SEC['KSI'] = None
        else:
            # TODO: no readily-available security context
            pass
        
        
        
        
        
        
                
        #
        return self.dispatch_nas(NasRxNosec)
    
    
    def dispatch_nas(self, NasRx):
        epd = NasRx[0]['EPD'].get_val()
        if epd == 126:
            return self.FGMM.process(NasRx)
        elif epd == 46:
            return self.FGSM.process(NasRx)
        else:
            self._log('WNG', 'invalid 5G NAS message, header: %r' % NasRx[0])
            return []
    
    
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
    
    def _get_paging_ies(self):
        guami = self.Server.AMF_GUAMI[self.UE.PLMN]
        # only supporting mandatory IEs
        IEs = {
            'TAIListForPaging': [{
                'tAI': {
                    'pLMNIdentity': plmn_str_to_buf(self.UE.PLMN),
                    'tAC': uint_to_bytes(self.UE.TAC, 24)
                    }
                }],
            'UEPagingIdentity': {
                'fiveG-S-TMSI': {
                    'aMFSetID': (guami[1], 10),
                    'aMFPointer': (guami[2], 6),
                    'fiveG-TMSI': uint_to_bytes(self.UE.FGTMSI, 32),
                    }
                }
            }
        #
        return IEs
    
    def page(self):
        """send NGAP Paging command to gNB responsible for the UE TAI
        """
        # send a NGAPPaging for the 5GS domain
        if self.connected.is_set():
            self._log('DBG', 'paging: UE already connected')
            return
        # get the set of gNBs serving the UE TAI
        # gNB id is 3-tuple whereas eNB id is 2-tuple
        tai = (self.UE.PLMN, self.UE.TAC)
        try:
            gnbs = [self.Server.RAN[gnbid] for gnbid in self.Server.TAI[tai] if len(gnbid) == 3]
        except Exception:
            self._log('ERR', 'paging: no gNB serving the UE TAI %s.%.6x' % tai)
            return
        #
        # only mandatory IEs supported yet
        IEs = self._get_paging_ies()
        #
        # start a NGAPPaging procedure on all gNBs
        for gnb in enbs:
            gnb.page(**IEs)
        self._log('INF', 'paging: ongoing')
    
    def page_block(self):
        """page the UE and wait for it to connect, or the paging procedure to timeout.
        Returns True if UE gets connected, False otherwise.
        """
        # send a NGAPPaging for the 5GS domain
        if self.connected.is_set():
            self._log('DBG', 'paging: UE already connected')
            return True
        # get the set of gNBs serving the UE TAI
        # gNB id is 3-tuple whereas eNB id is 2-tuple
        tai = (self.UE.PLMN, self.UE.TAC)
        try:
            gnbs = [self.Server.RAN[gnbid] for gnbid in self.Server.TAI[tai] if len(gnbid) == 3]
        except Exception:
            self._log('ERR', 'paging: no gNB serving the UE TAI %s.%.6x' % tai)
            return False
        #
        IEs = self._get_paging_ies()
        #
        # retries paging as defined in case UE does not connect
        i = 0
        while i <= self.PAG_RETR:
            # start an S1APPaging procedure on all RNCs
            for enb in enbs:
                enb.page(**IEs)
            # check until UE gets connected or timer expires
            if self.connected.wait(self.PAG_WAIT):
                self._log('INF', 'paging: UE connected')
                return True
            else:
                # timeout
                i += 1
        self._log('WNG', 'paging: timeout, UE not connected')
        return False
    
    def send_ng_rel(self, cause=('nas', 'normal-release')):
        """send an UEContextRelease over the NG link with the given NGAP cause
        """
        if not self.connected.is_set():
            # nothing to release
            self._log('DBG', 'release: UE not connected')
            return True
        # prepare the NGAPUEContextRelease procedure
        NgapProc = self.init_ngap_proc(NGAPUEContextRelease, Cause=cause)
        if not NgapProc:
            return False
        if not self.transmit_ngap_proc([NgapProc]):
            return False
        else:
            return True
    
    def send_ng_err(self, cause, **IEs):
        """send an ErrorIndication over the NG link with the given AP cause
        IEs can contain any of the optional or extended IEs: CriticalityDiagnostics
        """
        if not self.connected.is_set():
            # NGAP link disconnected
            if self.NGAP_FORCE_PAGE:
                # force to connect
                if not self._net_init_con():
                    # unable to connect with the UE
                    return False
            else:
                return False
        # prepare the S1AP procedure
        IEs['Cause'] = cause
        NgapProc = self.init_ngap_proc(NGAPErrorIndCN, **IEs)
        if not NgapProc:
            return False
        if not self.transmit_s1ap_proc([NgapProc]):
            return False
        else:
            return True
    
    
    #--------------------------------------------------------------------------#
    # to send arbitrary NAS buffers to the UE
    #--------------------------------------------------------------------------#
    # TODO
    
    
    #--------------------------------------------------------------------------#
    # 5G bearer activation
    #--------------------------------------------------------------------------#
    # TODO
    

