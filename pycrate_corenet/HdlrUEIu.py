# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.1
# *
# * Copyright © 2017. Benoit Michau. ANSSI.
# *
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License
# * as published by the Free Software Foundation; either version 2
# * of the License, or (at your option) any later version.
# * 
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# * 
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# * 02110-1301, USA.
# *
# *--------------------------------------------------------
# * File Name : pycrate_corenet/HdlrUEIu.py
# * Created : 2017-07-11
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from .utils       import *
from .ProcCNRanap import *


class _UEIuSigStack(SigStack):
    
    # to keep track of all RANAP procedures
    TRACK_PROC = True
    
    # reference to the UEd
    UE  = None
    # reference to the HNBd
    RNC = None
    
    #--------------------------------------------------------------------------#
    # global security policy
    #--------------------------------------------------------------------------#
    # this will systematically bypass all auth and smc procedures during 
    # UE signaling procedures
    SEC_DISABLED = False
    #
    # format of the security context dict self.SEC:
    # self.SEC is a dict of available 2G / 3G security contexts indexed by CKSN,
    # and current CKSN in use
    #
    # when self.SEC['CKSN'] is not None, the context is enabled at the RNC, e.g.
    # self.SEC = {'CKSN': 0,
    #             0: {'CK': b'...', 'IK': b'...', 'UEA': 1, 'UIA': 0, 'CTX': 3},
    #             ...}
    # 
    # a single security context contains:
    # CK, IK: 16 bytes buffer, keys to be sent to the RNC during the smc procedure
    # UEA, UIA: algo index, indicated by the RNC at the end of a successful smc procedure
    # CTX: context of the authentication,
    #    2 means 2G auth converted to 3G context
    #    3 means 3G auth and native context
    
    #--------------------------------------------------------------------------#
    # RANAPSecurityModeControl policy
    #--------------------------------------------------------------------------#
    # lists of algorithms priority
    # -> il will be sent as is to the RNC into the SMC
    # -> the RNC will deal with the UE to select one
    SMC_UEA = [2, 1, 0] # UEA2, UEA1, UEA0
    SMC_UIA = [1, 0]    # UIA2, UIA1, UIA0 is not defined in UMTS
    #
    # dummy security context in case an SMC has to be run 
    # but no security context exists
    SMC_DUMMY = {'CK': 16*b'\0', 'IK': 16*b'\0', 'UEA': None, 'UIA': []}
    
    
    def _log(self, logtype, msg):
        self.UE._log(logtype, '[%s: %i] %s' % (self.__class__.__name__, self.CtxId, msg))
    
    def __init__(self, ued, hnbd, ctx_id):
        self.UE = ued
        self.Server = ued.Server
        #
        # dict of ongoing RANAP procedures (indexed by their procedure code)
        self.Proc = {}
        # procedure code of the last RANAP procedure emitting a PDU toward the RAN
        self.ProcLast = None
        # list of tracked procedures (requires TRACK_PROC = True)
        self._proc = []
        #
        # RANAP callback for NAS stacks
        self.RanapTx = None
        #
        # dict of available 2G / 3G security contexts, indexed by CKSN
        # and current CKSN in use
        self.SEC = {}
        self.reset_sec_ctx()
        #
        self.set_ran(hnbd)
        self.set_ctx(ctx_id)
    
    def set_ran(self, hnbd):
        self.SEC['CKSN'] = None
        self.RNC = hnbd
    
    def unset_ran(self):
        del self.RNC
        self.SEC['CKSN'] = None
    
    def set_ctx(self, ctx_id):
        self.CtxId = ctx_id
    
    def unset_ctx(self):
        self.CtxId = -1
    
    def set_sec_ctx(self, cksn, ctx, vect):
        if ctx == 3:
            # 3G sec ctx
            ctx = {'VEC': vect,
                   'CTX': ctx,
                   'CK' : vect[3],
                   'IK' : vect[4],
                   'UEA': self.SMC_UEA,
                   'UIA': self.SMC_UIA}
        else:
            # ctx == 2, 2G sec ctx
            # convert 2G Kc to 3G Ck, Ik
            CK, IK = conv_C4(vect[2]), conv_C5(vect[2])
            ctx = {'VEC': vect,
                   'CTX': ctx,
                   'CK' : CK,
                   'IK' : IK,
                   'UEA': self.SMC_UEA,
                   'UIA': self.SMC_UIA}
        self.SEC[cksn]   = ctx
        self.SEC['CKSN'] = cksn
    
    def get_new_cksn(self):
        for i in range(0, 7):
            if i not in self.SEC:
                return i
        # all CKSN have been used, clear all of them except the current one
        cur = self.SEC['CKSN']
        l = list(range(0, 7))
        if cur is not None:
            l.remove(cur)
        [self.SEC.pop(i) for i in l]
        if cur == 0:
            return 1
        else:
            return 0
    
    def process_ranap(self, buf):
        """process a RANAP PDU buffer sent by the RNC handling the UE connection
        and return a list with RANAP PDU(s) to be sent back to the RNC
        """
        # decode the RANAP PDU
        errcause = None
        try:
            PDU_RANAP.from_aper(buf)
        except:
            # unable to decode APER-encoded buffer
            self._log('WNG', 'invalid RANAP PDU: %s' % hexlify(buf).decode('ascii'))
            # returns a RANAP error ind: protocol, transfer-syntax-error
            errcause = ('protocol', 97)
            Proc = RANAPErrorIndCN(self)
            Proc.encode_pdu('ini', Cause=errcause)
            if self.TRACK_PROC:
                # keep track of the procedure
                self._proc.append( Proc )
            self.ProcLast = Proc.Code
            return Proc.send()
        #
        if self.DOM == 'CS' and self.UE.TRACE_ASN_RANAP_CS:
            self._log('TRACE_ASN_RANAP_CS_UL', '\n' + PDU_RANAP.to_asn1())
        elif self.DOM == 'PS' and self.UE.TRACE_ASN_RANAP_PS:
            self._log('TRACE_ASN_RANAP_PS_UL', '\n' + PDU_RANAP.to_asn1())
        pdu = PDU_RANAP()
        #
        if pdu[0] == 'initiatingMessage':
            # RNC-initiated procedure, create it through the dispatcher
            try:
                Proc = RANAPProcRncDispatcher[pdu[1]['procedureCode']](self)
            except:
                self._log('ERR', 'invalid RANAP PDU, initiatingMessage, code %i'\
                          % pdu[1]['procedureCode'])
                # returns a RANAP error ind: protocol, abstract-syntax-error-reject
                errcause = ('protocol', 100)
                Proc = RANAPErrorIndCN(self)
                Proc.encode_pdu('ini', Cause=errcause)
            else:
                # store the procedure, if no error ind
                self.Proc[Proc.Code] = Proc
            if self.TRACK_PROC:
                # keep track of the procedure
                self._proc.append( Proc )
            # process the PDU within the procedure
            Proc.recv( pdu )
            #
            if Proc.Cont['suc'] is not None or errcause is not None:
                # set the last procedure code
                self.ProcLast = Proc.Code
                # send back any potential response to the RNC
                # Proc.send() will take care to clean-up self.Proc
                return self._encode_pdu(Proc.send())
            else:
                # potentially create new RANAP procedures, 
                # as outcome of the one received
                snd = []
                for ProcRet in Proc.trigger():
                    # all those procedures must have been initiated with self.init_ranap_proc()
                    # hence, they are already set in self.Proc
                    # and tracked in self._proc
                    # add ProcRet to the stack of ongoing procedure
                    snd.extend( ProcRet.send() )
                    # set the last procedure code
                    self.ProcLast = ProcRet.Code
                return self._encode_pdu(snd)
        #
        else:
            # CN-initiated procedure, already existing in self.Proc
            # transfer the PDU to it
            try:
                Proc = self.Proc[pdu[1]['procedureCode']]
            except:
                self._log('ERR', 'invalid RANAP PDU, %s, code %i' % (pdu[0], pdu[1]['procedureCode']))
                # returns a RANAP error ind: protocol, message-not-compatible-with-receiver-state
                errcause = ('protocol', 99)
                Proc = RANAPErrorIndCN(self)
                Proc.encode_pdu('ini', Cause=errcause)
                if self.TRACK_PROC:
                    # keep track of the procedure
                    self._proc.append( Proc )
            # process the PDU within the procedure
            Proc.recv( pdu )
            #
            if errcause is not None:
                # set the last procedure code
                self.ProcHnbapLast = Proc.Code
                # send back any potential response to the RNC
                # Proc.send() will take care to clean-up self.Proc
                return self._encode_pdu(Proc.send())
            else:
                # potentially create new RANAP procedures, as outcome of the one received
                snd = []
                for ProcRet in Proc.trigger():
                    # all those procedures must have been initiated with self.init_ranap_proc()
                    # hence, they are already set in self.Proc
                    # and tracked in self._proc
                    # add ProcRet to the stack of ongoing procedure
                    snd.extend( ProcRet.send() )
                    # set the last procedure code
                    self.ProcLast = ProcRet.Code
                return self._encode_pdu(snd)
    
    def _encode_pdu(self, pdus):
        ret = []
        for pdu in pdus:
            try:
                PDU_RANAP.set_val(pdu)
            except Exception as err:
                self._log('ERR', 'unable to set the RANAP pdu value')
                self._errpdu = pdu
            else:
                if self.DOM == 'CS' and self.UE.TRACE_ASN_RANAP_CS:
                    self._log('TRACE_ASN_RANAP_CS_DL', '\n' + PDU_RANAP.to_asn1())
                elif self.DOM == 'PS' and self.UE.TRACE_ASN_RANAP_PS:
                    self._log('TRACE_ASN_RANAP_PS_DL', '\n' + PDU_RANAP.to_asn1())
                ret.append( PDU_RANAP.to_aper() )
        return ret
    
    def init_ranap_proc(self, ProcClass, **kw):
        """initialize a CN-initiated RANAP procedure of class `ProcClass',
        encode the initiatingMessage PDU with given **kw and return the procedure
        """
        if ProcClass.Code in self.Proc:
            self._log('ERR', 'a RANAP procedure %s is already ongoing, unable to start a new one'\
                      % ProcClass.__name__)
            return None
        try:
            Proc = ProcClass(self)
        except:
            # self has no active Iu link
            self._log('ERR', 'no active Iu link to start a RANAP procedure %s' % ProcClass.__name__)
            return None
        # store the procedure
        self.Proc[Proc.Code] = Proc
        if self.TRACK_PROC:
            # keep track of the procedure
            self._proc.append( Proc )
        Proc.encode_pdu('ini', **kw)
        return Proc
    
    def ret_ranap_dt(self, NAS_PDU):
        # return a RANAPDirectTransfer with the NAS PDU to be sent
        RanapProc = self.init_ranap_proc(RANAPDirectTransferCN,
                                         NAS_PDU=NAS_PDU.to_bytes(),
                                         SAPI='sapi-0')
        if RanapProc:
            return [RanapProc]
        else:
            return []
    
    #--------------------------------------------------------------------------#
    # helper methods
    #--------------------------------------------------------------------------#
    
    def get_smc_ies(self, cksn=None, newkey=False):
        # if CKSN is None, take the 1st available
        if cksn is None:
            cksn = self._get_any_cksn()
        try:
            secctx = self.SEC[cksn]
        except KeyError:
            # no security ctxt available at all
            self._log('WNG', 'no security context available, using SMC_DUMMY')
            secctx = self.SMC_DUMMY
        # prepare the kwargs for encoding the SMC encoding
        IEs = {}
        if self.SMC_UIA is not None:
            IEs['IntegrityProtectionInformation'] = \
                {'permittedAlgorithms': self.SMC_UIA,
                 'key': (bytes_to_uint(secctx['IK'], 128), 128)}
        if self.SMC_UEA is not None:
            IEs['EncryptionInformation'] = \
                {'permittedAlgorithms': self.SMC_UEA,
                 'key': (bytes_to_uint(secctx['CK'], 128), 128)}
        if newkey:
            # taking a new context into use, i.e. just after an auth
            IEs['KeyStatus'] = 'new'
        else:
            IEs['KeyStatus'] = 'old'
        #
        return IEs
    
    def _get_any_cksn(self):
        if self.SEC['CKSN'] is not None:
            try:
                return self.SEC[self.SEC['CKSN']]
            except:
                # given CKSN not available anymore
                self.SEC['CKSN'] = None
        #
        for i in range(0, 7):
            if i in self.SEC:
                self.SEC['CKSN'] = i
                return i
        return None
    
    def get_new_cksn(self):
        ra = range(0, 7)
        for cksn in ra:
            if cksn not in self.SEC:
                # return the 1st CKSN available
                return cksn
        # all CKSN are defined
        if self.SEC['CKSN'] is None:
            # delete all defined CKSN
            [self.SEC.__delitem__(i) for i in ra]
            # return the 1st
            return 0
        else:
            # delete all except the one in use
            ra = list(ra)
            ra.remove( self.SEC['CKSN'] )
            [self.SEC.__delitem__(i) for i in ra]
            return ra[0]

