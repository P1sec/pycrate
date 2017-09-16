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
# * File Name : pycrate_corenet/Server.py
# * Created : 2017-06-28
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

#------------------------------------------------------------------------------#
# This is the main corenet server
# 
# It serves connection to:
# - eNodeB and Home-eNodeB over S1AP
# - Home-NodeB over HNBAP and RUA
# 
# It handles signalling trafic for UE
# and connects them to specific service handler (SMS, GTPU, ...)
#------------------------------------------------------------------------------#

from .utils     import *
from .HdlrHNB   import HNBd
from .HdlrENB   import ENBd
from .HdlrUE    import UEd
from .ServerAuC import AuC


# to log all the SCTP socket send() / recv() calls
DEBUG_SK = False

# global HNB debug level
HNBd.DEBUG = ('ERR', 'WNG', 'INF') #, 'DBG')
HNBd.TRACE_ASN_HNBAP = False
HNBd.TRACE_ASN_RUA   = False
HNBd.TRACE_ASN_RANAP = False
# global eNB debug level
ENBd.DEBUG = ('ERR', 'WNG', 'INF') #, 'DBG')
ENBd.TRACE_ASN_S1AP  = False
# global UE debug level
UEd.DEBUG  = ('ERR', 'WNG', 'INF', 'DBG')
UEd.TRACE_RANAP_CS   = False
UEd.TRACE_RANAP_PS   = False
UEd.TRACE_S1AP       = False
UEd.TRACE_NAS_CS     = False
UEd.TRACE_NAS_PS     = True
UEd.TRACE_NAS_EMMENC = True
UEd.TRACE_NAS_EPS    = True


class CorenetServer(object):
    
    #--------------------------------------------------------------------------#
    # debug and tracing level
    #--------------------------------------------------------------------------#
    #
    # verbosity level: list of log types to display when calling self._log(logtype, msg)
    DEBUG    = ('ERR', 'WNG', 'INF', 'DBG')
    # to log SCTP socket send() / recv() content
    TRACE_SK = False
    
    #--------------------------------------------------------------------------#
    # network server settings
    #--------------------------------------------------------------------------#
    #
    # SCTP sockets recv() buffer length
    SERVER_BUFLEN = 16384
    SERVER_MAXCLI = 16
    #
    # HNBAP server
    SERVER_HNB = {'INET'  : socket.AF_INET,
                  'IP'    : '10.1.1.1',
                  #'IP'    : '127.0.1.1',
                  'port'  : 29169,
                  'MAXCLI': SERVER_MAXCLI,
                  'errclo': True}
    #SERVER_HNB = {} # disabling HNB server
    # S1AP server
    SERVER_ENB = {'INET'  : socket.AF_INET,
                  'IP'    : '127.0.1.1',
                  'port'  : 36412,
                  'MAXCLI': SERVER_MAXCLI,
                  'errclo': False}
    SERVER_ENB = {} # disabling S1AP server
    #
    # Server scheduler resolution:
    # This is the resolution (in sec) for the Server to check the list of registered UE,
    # and check for ongoing NAS procedures potentially in timeout.
    # This is also applied as a timeout on the main select() loop.
    SCHED_RES = 0.1
    # This is the flag for enabling the cleaning of NAS procedures on timeout
    SCHED_UE_TO = True
    
    #--------------------------------------------------------------------------#
    # corenet service handlers
    #--------------------------------------------------------------------------#
    # These are references to services handlers
    #
    # Authentication Centre
    AUCd  = AuC
    # GTPU trafic forwarder
    GTPUd = None
    # SMS center
    SMSd = None
    
    #--------------------------------------------------------------------------#
    # corenet global config parameters
    #--------------------------------------------------------------------------#
    #
    # main PLMN served
    PLMN = '20869'
    # equivalent PLMNs served
    # None or list of PLMNs ['30124', '763326', ...]
    EQUIV_PLMN = None
    # emergency number lists
    # None or list of 2-tuple [(number_category, number), ...]
    # number_category is a 5 bit uint set of flags (Police, Ambulance, Fire, Marine, Mountain)
    # number is a digits string
    EMERG_NUMS = None
    #
    # S1 connection MME parameters
    ConfigS1    = {}
    # HNBAP connection GW parameters
    ConfigHNBAP = {}
    # RUA connection GW parameters
    ConfigRUA   = {}
    # RANAP connection IuCS core parameters
    ConfigIuCS  = {
        'EquivPLMNList': EQUIV_PLMN,
        'EmergNumList' : EMERG_NUMS,
        }
    # RANAP connection IuPS core parameters
    ConfigIuPS  = {
        'EquivPLMNList': EQUIV_PLMN,
        'EmergNumList' : EMERG_NUMS,
        }
    
    #--------------------------------------------------------------------------#
    # HNB and ENB parameters
    #--------------------------------------------------------------------------#
    #
    # Home-NodeB, eNodeB and Home-eNodeB, indexed by (PLMN, CellId)
    RAN = {}
    #
    # This is a flag to allow any RAN equipment to connect the CorenetServer
    # If enabled, HNB and ENB dict will be populated at runtime
    # If disabled, HNB and ENB keys (PLMN, CellID) needs to be setup
    RAN_CONNECT_ANY = True
    #
    # This is the list of accepted PLMN for RAN equipment connecting
    RAN_ALLOWED_PLMN = [PLMN]
    
    #--------------------------------------------------------------------------#
    # UE parameters
    #--------------------------------------------------------------------------#
    #
    # UE configuration parameters
    ConfigUE = {
        '*': {'IPAddr': (1, '192.168.132.199'), # PDN type (1:IPv4, 2:IPv6, 3:IPv4v6), IP address
              'MSISDN': '0123456789', # phone number
              'USIM'  : True, # Milenage supported
              },
        # $IMSI: {IPaddr, MSISDN, USIM, ...}
        }
    #
    # UE, indexed by IMSI, and their UEd handler instance
    UE = {}
    # UE, indexed by TMSI when the IMSI is unknown (at attachment), 
    # and their UEd handler instance are set in ._UEpre, created at init
    #
    # TMSI / P-TMSI / M-TMSI to IMSI conversion
    TMSI  = {}
    PTMSI = {}
    MTMSI = {}
    #
    # This is a filter which enables the potential attachment of non-preconfigured 
    # UE to the CorenetServer
    # WNG: for IMSI that are not preconfigured (no Ki in the AuC database),
    # further UE-related procedure will fail because of missing crypto material.
    # When an non-preconfigured UE attaches the CorenetServer, ConfigUE['*'] is 
    # used to provide a default config and need to be defined.
    # use UE_ATTACH_FILTER = None to disable this permissive filter.
    UE_ATTACH_FILTER = r'^20869'
    
    #--------------------------------------------------------------------------#
    # logging and init methods
    #--------------------------------------------------------------------------#
    
    def _log(self, logtype, msg):
        """Server logging facility
        
        DEBUG logtype: 'ERR', 'WNG', 'INF', 'DBG'
        TRACE logtype: 'TRACE_SK_[UL|DL]',
                       'TRACE_ASN_[HNBAP|RUA|S1AP]_[UL|DL]',
        """
        if logtype[:3] == 'TRA':
            if logtype[6:8] == 'SK':
                log('[TRA] [%s]\n%s%s%s'\
                    % (logtype[6:], TRACE_COLOR_START, hexlify(msg).decode('ascii'), TRACE_COLOR_END))
            else:
                log('[TRA] [%s]\n%s%s%s'\
                    % (logtype[6:], TRACE_COLOR_START, msg, TRACE_COLOR_END))
        elif logtype in self.DEBUG:
            log('[%s] %s' % (logtype, msg))
    
    def __init__(self, serving=True, threaded=True):
        # initialize the Python built-in Mersennes Twister LFSR for producing TMSI
        random.seed(random.SystemRandom().randint(0, 1<<64))
        # starting the server in background
        self._running = False
        if threaded:
            self._server = threadit(self.start, **{'serving':serving})
        else:
            self.start(serving=serving)
    
    #--------------------------------------------------------------------------#
    # SCTP socket server
    #--------------------------------------------------------------------------#
    
    def start(self, serving=True):
        #
        # start SCTP servers, bind() and listen()
        self.SCTPServ   = [] # will be casted to tuple
        if DEBUG_SK:
            self._skc   = []
        # LUT for connected SCTP client and ENBId / HNBId
        self.SCTPCli    = {}
        #
        if self.SERVER_HNB:
            self._start_hnb_server()
            self.SCTPServ.append( self._sk_hnb )
        else:
            self._sk_hnb = None
        if self.SERVER_ENB:
            self._start_enb_server()
            self.SCTPServ.append( self._sk_enb )
        else:
            self._sk_enb = None
        self.SCTPServ = tuple(self.SCTPServ)
        #
        # init the dict for storing UE with unknown IMSI at attachment
        self._UEpre = {}
        #
        # start sub-servers
        if self.AUCd:
            self.AUCd  = self.AUCd()
        if self.GTPUd:
            self.GTPUd = self.GTPUd()
        if self.SMSd:
            self.SMSd  = self.SMSd()
        #
        if serving:
            # serve connections
            self._serve()
            # self._running has been set to False, main loop exited
            self._log('INF', 'SCTP server stopped')
    
    def is_running(self):
        return self._running
    
    def _start_hnb_server(self):
        # start SCTP server for Home-NodeBs
        server_addr = (self.SERVER_HNB['IP'], self.SERVER_HNB['port'])
        try:
            self._sk_hnb = sctp.sctpsocket_tcp(self.SERVER_HNB['INET'])
            self.sctp_set_events(self._sk_hnb)
        except Exception as err:
            raise(CorenetErr('cannot create SCTP socket: {0}'.format(err)))
        try:
            self._sk_hnb.bind(server_addr)
        except Exception as err:
            raise(CorenetErr('cannot bind SCTP socket on address {0!r}: {1}'\
                  .format(server_addr, err)))
        try:
            self._sk_hnb.listen(self.SERVER_HNB['MAXCLI'])
        except Exception as err:
            raise(CorenetErr('cannot listen to SCTP connection: {1}'.format(err)))
        #
        self._log('INF', 'SCTP HNB server started on address %r' % (server_addr, ))
    
    def _start_enb_server(self):
        # start SCTP server for eNodeBs
        server_addr = (self.SERVER_ENB['IP'], self.SERVER_ENB['port'])
        try:
            self._sk_enb = sctp.sctpsocket_tcp(self.SERVER_ENB['INET'])
            #self._sk_enb.set_adaptation(self.SERVER_ENB['ppid'])
            self.sctp_set_events(self._sk_enb)
        except Exception as err:
            raise(CorenetErr('cannot create SCTP socket: {0}'.format(err)))
        try:
            self._sk_enb.bind(server_addr)
        except Exception as err:
            raise(CorenetErr('cannot bind SCTP socket on address {0!r}: {1}'\
                  .format(server_addr, err)))
        try:
            self._sk_enb.listen(self.SERVER_ENB['MAXCLI'])
        except Exception as err:
            raise(CorenetErr('cannot listen to SCTP connection: {1}'.format(err)))
        #
        self._log('INF', 'SCTP ENB server started on address %r' % (server_addr, ))
    
    def _serve(self):
        # Main server loop, using select() to read sockets, the loop:
        # gets new SCTP clients,
        # gets new SCTP streams for connected SCTP clients,
        # and eventually timeouts running UE NAS procedures
        self._running, T0 = True, time()
        while self._running:
            skr = []
            try:
                skr = select(self.SCTPServ + tuple(self.SCTPCli), (), (), self.SCHED_RES)[0]
            except Exception as err:
                self._log('ERR', 'select() error: %s' % err)
                self._running = False
            #
            for sk in skr:
                if sk == self._sk_enb:
                    # new eNodeB STCP client (S1SetupRequest)
                    self.handle_new_enb()
                elif sk == self._sk_hnb:
                    # new Home-NodeB SCTP client (HNBRegisterRequest)
                    self.handle_new_hnb()
                else:
                    # read from connected SCTP client for a new stream 
                    # (whatever PDU)
                    self.handle_stream_msg(sk)
            #
            # clean-up potential signalling procedures in timeout
            if self.SCHED_UE_TO:
                if not skr or time() - T0 > self.SCHED_RES:
                    # select() timeout or more than `SCHED_RES' seconds since 
                    # last timeout
                    self.clean_ue_proc()
                    T0 = time()
    
    def stop(self):
        self._running = False
        sleep(self.SCHED_RES + 0.01)
        if self._sk_hnb:
            self._sk_hnb.close()
        if self._sk_enb:
            self._sk_enb.close()
        #
        # disconnect all RAN clients
        for cli in self.SCTPCli:
            cli.close()
            self.RAN[self.SCTPCli[cli]].disconnect()
        self.SCTPCli.clear()
        #
        # stop sub-servers
        self.AUCd.stop()
    
    def sctp_handle_notif(self, sk, notif):
        self._log('DBG', 'SCTP notification: type %i, flags %i' % (notif.type, notif.flags))
        # TODO
    
    def sctp_set_events(self, sk):
        # configure the SCTP socket to receive the adaptation layer indication
        # in sctp_recv() notification
        sk.events.adaptation_layer = True
        sk.events.data_io          = True
        sk.events.flush()
        
    #--------------------------------------------------------------------------#
    # SCTP stream handler
    #--------------------------------------------------------------------------#
    
    def _read_sk(self, sk):
        # we always arrive there after a select() call, 
        # hence, recv() should always return straight without blocking
        # TODO: loop on recv() to get the complete stream (in case of very long PDU...), 
        # then defragment those PDUs properly
        # TODO: in case notif has only 0, specific events need to be subscribed 
        # to get at least ppid and stream
        try:
            addr, flags, buf, notif = sk.sctp_recv(self.SERVER_BUFLEN)
        except TimeoutError as err:
            # the client disconnected
            if sk in self.SCTPCli:
                self._rem_sk(sk)
                return None, None
        if DEBUG_SK:
            self._skc.append( ('recv', time(), addr, flags, buf, notif) )
        if not buf:
            if flags & sctp.FLAG_NOTIFICATION:
                # SCTP notification
                self.sctp_handle_notif(sk, notif)
            elif sk in self.SCTPCli:
                # the client just disconnected
                self._rem_sk(sk)
        else:
            if self.TRACE_SK:
                self._log('TRACE_SK_UL', buf)
            if not flags & sctp.FLAG_EOR:
                self._log('WNG', 'SCTP message truncated') 
        return buf, notif
    
    def _rem_sk(self, sk):
        # close socket
        sk.close()
        # select RAN client
        cli = self.RAN[self.SCTPCli[sk]]
        if isinstance(cli, HNBd):
            self._log('DBG', 'HNB %r closed connection' % (cli.ID,))
        elif isinstance(cli, ENBd):
            self._log('DBG', 'eNB %r closed connection' % (cli.ID,))
        else:
            assert()
        # update HNB / ENB state
        cli.disconnect()
        # update list of clients socket, and dict of RAN clients
        del self.SCTPCli[sk]
    
    def _write_sk(self, sk, buf, ppid=0, stream=0):
        if self.TRACE_SK:
            self._log('TRACE_SK_DL', buf)
        if ppid:
            ppid = socket.htonl(ppid)
        if stream:
            stream = socket.htonl(stream)
        try:
            ret = sk.sctp_send(buf, ppid=ppid, stream=stream)
        except Exception as err:
            self._log('ERR', 'cannot send buf to SCTP client at address %r' % (sk.getpeername(), ))
            if DEBUG_SK:
                self._skc.append( ('send', time(), buf, ppid, stream, err) )
        else:
            if DEBUG_SK:
                self._skc.append( ('send', time(), buf, ppid, stream) )
    
    # Connecting an eNodeB
    # TODO
    
    def handle_new_enb(self):
        sk, addr = self._sk_enb.accept()
        self._log('DBG', 'New eNB client from address %r' % (addr, ))
        #
        buf, notif = self._read_sk(sk)
        if not buf:
            # WNG: maybe required to handle SCTP notification, at some point
            return
        try:
            PDU_S1AP.from_aper(buf)
        except:
            self._log('WNG', 'invalid S1AP PDU: %s' % hexlify(buf).decode('ascii'))
            return
        pdu = PDU_S1AP()
        # to be completed
    
    
    # Connecting a Home-NodeB
    
    def _parse_hnbregreq(self, pdu):
        if pdu[0] != 'initiatingMessage':
            self._log('WNG', 'invalid HNBAP PDU for registering the HNB')
            return
        if pdu[1]['procedureCode'] != 1:
            # not HNBRegisterRequest
            self._log('WNG', 'invalid HNBAP PDU for registering the HNB')
            return
        IEs, Exts = pdu[1]['value'][1]['protocolIEs'], pdu[1]['value'][1]['protocolExtensions']
        plmn, cellid = None, None
        for ie in IEs:
            if ie['id'] == 9:
                plmn = ie['value'][1]
            elif ie['id'] == 11:
                cellid = ie['value'][1]
            if plmn is not None and cellid is not None:
                break
        if plmn is None or cellid is None:
            self._log('WNG', 'invalid HNBAP PDU for registering the HNB: missing PLMN and CellID')
            return
        # decode PLMN and CellID
        try:
            PLMN   = plmn_buf_to_str(plmn)
            CellID = cellid_bstr_to_str(cellid)
            return PLMN, CellID
        except:
            return None, None
    
    def _send_hnbregrej(self, sk, cause):
        IEs = [{'criticality': 'ignore',
                'id': 1, # id-Cause
                'value': (('HNBAP-IEs', 'Cause'), cause)}]
        pdu = ('unsuccessfulOutcome',
               {'criticality': 'ignore',
                'procedureCode': 1,
                'value': (('HNBAP-PDU-Contents', 'HNBRegisterReject'),
                          {'protocolIEs' : IEs})})
        PDU_HNBAP.set_val(pdu)
        if HNBd.TRACE_ASN_HNBAP:
            self._log('TRACE_ASN_HNBAP_DL', PDU_HNBAP.to_asn1())
        self._write_sk(sk, PDU_HNBAP.to_aper(), ppid=SCTP_PPID_HNBAP)
        if self.SERVER_HNB['errclo']:
            sk.close()
    
    def handle_new_hnb(self):
        sk, addr = self._sk_hnb.accept()
        self._log('DBG', 'New HNB client from address %r' % (addr, ))
        #
        buf, notif = self._read_sk(sk)
        if not buf:
            # WNG: maybe required to handle SCTP notification, at some point
            return
        # verifying SCTP Payload Protocol ID
        ppid = socket.ntohl(notif.ppid)
        if ppid != SCTP_PPID_HNBAP:
            self._log('ERR', 'invalid HNBAP PPID, %i' % ppid)
            if self.SERVER_HNB['errclo']:
                sk.close()
            return
        #
        try:
            PDU_HNBAP.from_aper(buf)
        except:
            self._log('WNG', 'invalid HNBAP PDU: %s' % hexlify(buf).decode('ascii'))
            return
        if HNBd.TRACE_ASN_HNBAP:
            self._log('TRACE_ASN_HNBAP_UL', PDU_HNBAP.to_asn1())
        pdu = PDU_HNBAP()
        #
        # ensure we have a HNBRegisterRequest with PLMN and CellID provided
        HNBId = self._parse_hnbregreq(pdu)
        if HNBId is None:
            # send HNBRegisterReject
            self._send_hnbregrej(sk, cause=('protocol', 'abstract-syntax-error-reject'))
            return
        elif HNBId not in self.RAN:
            if not self.RAN_CONNECT_ANY:
                self._log('ERR', 'HNB %r not allowed to connect' % (HNBId,))
                # send HNBRegisterReject
                self._send_hnbregrej(sk, cause=('radioNetwork', 'unauthorised-HNB'))
                return
            elif HNBId[0] not in self.RAN_ALLOWED_PLMN:
                self._log('ERR', 'HNB %r not allowed to connect, bad PLMN' % (HNBId,))
                self._send_hnbregrej(sk, cause=('radioNetwork', 'unauthorised-HNB'))
                return
            else:
                # creating an entry for this HNB
                self.RAN[HNBId] = HNBd(self, sk)
                ret = self.RAN[HNBId].process_hnbap_pdu(pdu)
        else:
            if self.RAN[HNBId] is None:
                # HNB allowed, but not yet connected
                self.RAN[HNBId] = HNBd(self, sk)
                ret = self.RAN[HNBId].process_hnbap_pdu(pdu)
            elif not self.RAN[HNBId].is_connected():
                # HNB already connected and disconnected in the past
                self.RAN[HNBId].__init__(self, sk)
                ret = self.RAN[HNBId].process_hnbap_pdu(pdu)
            else:
                # HNB already connected
                self._log('ERR', 'HNB %r already connected from address %r'\
                          % (HNBId, self.RAN[HNBId].SK.getpeername()))
                if self.SERVER_HNB['errclo']:
                    sk.close()
                return
        #
        # keep track of the client
        self.SCTPCli[sk] = HNBId
        # send available PDU(s) back
        for retpdu in ret:
            PDU_HNBAP.set_val(retpdu)
            if HNBd.TRACE_ASN_HNBAP:
                self._log('TRACE_ASN_HNBAP_DL', PDU_HNBAP.to_asn1())
            self._write_sk(sk, PDU_HNBAP.to_aper(), ppid=SCTP_PPID_HNBAP)
    
    
    def handle_stream_msg(self, sk):
        buf, notif = self._read_sk(sk)
        if not buf:
            # WNG: maybe required to handle SCTP notification, at some point
            return
        # getting SCTP PPID
        ppid = socket.ntohl(notif.ppid)
        # PPID is HNBAP or RUA
        if ppid == SCTP_PPID_HNBAP:
            try:
                PDU_HNBAP.from_aper(buf)
            except:
                self._log('WNG', 'invalid HNBAP PDU: %s' % hexlify(buf).decode('ascii'))
            pdu   = PDU_HNBAP()
            HNBId = self.SCTPCli[sk]
            Hnbd  = self.RAN[HNBId]
            if Hnbd.TRACE_ASN_HNBAP:
                Hnbd._log('TRACE_ASN_HNBAP_UL', PDU_HNBAP.to_asn1())
            ret   = Hnbd.process_hnbap_pdu(pdu)
        elif ppid == SCTP_PPID_RUA:
            try:
                PDU_RUA.from_aper(buf)
            except:
                self._log('WNG', 'invalid RUA PDU: %s' % hexlify(buf).decode('ascii'))
            pdu   = PDU_RUA()
            HNBId = self.SCTPCli[sk]
            Hnbd  = self.RAN[HNBId]
            if Hnbd.TRACE_ASN_RUA:
                Hnbd._log('TRACE_ASN_RUA_UL', PDU_HNBAP.to_asn1())
            ret   = Hnbd.process_rua_pdu(pdu)
        else:
            self._log('ERR', 'invalid SCTP PPID, %i' % ppid)
            if self.SERVER_HNB['errclo']:
                self._rem_sk(sk)
            return
        #
        # send available PDU(s) back
        if ppid == SCTP_PPID_HNBAP:
            for retpdu in ret:
                PDU_HNBAP.set_val(retpdu)
                if Hnbd.TRACE_ASN_HNBAP:
                    Hnbd._log('TRACE_ASN_HNBAP_DL', PDU_HNBAP.to_asn1())
                self._write_sk(sk, PDU_HNBAP.to_aper(), ppid=SCTP_PPID_HNBAP)
        else:
            for retpdu in ret:
                PDU_RUA.set_val(retpdu)
                if Hnbd.TRACE_ASN_RUA:
                    Hnbd._log('TRACE_ASN_RUA_DL', PDU_RUA.to_asn1())
                self._write_sk(sk, PDU_RUA.to_aper(), ppid=SCTP_PPID_RUA)
    
    
    #--------------------------------------------------------------------------#
    # UE handler
    #--------------------------------------------------------------------------#
    
    def get_ued(self, **kw):
        """return a UEd instance or None, according to the UE identity provided
        
        kw: imsi (digit-str), tmsi (uint32) or ptmsi (uint32)
        
        If an imsi is provided, returns the UEd instance in case the IMSI is allowed
        If a tmsi or ptmsi is provided, returns
            the UEd instance corresponding to this TMSI if already available
            a new UEd instance which will take care of requesting the IMSI
        """
        if 'imsi' in kw:
            imsi = kw['imsi']
            if imsi in self.UE:
                # UEd already available
                return self.UE[imsi]
            elif imsi in self.ConfigUE:
                # UEd has to be instantiated
                self.UE[imsi] = UEd(self, imsi, config=self.ConfigUE[imsi])
                return self.UE[imsi]
            elif self.UE_ATTACH_FILTER and re.match(self.UE_ATTACH_FILTER, imsi) and \
            '*' in self.ConfigUE:
                self._log('WNG', 'attaching an UE without dedicated configuration, IMSI %s' % imsi)
                self.UE[imsi] = UEd(self, imsi, config=self.ConfigUE['*'])
                return self.UE[imsi]
        elif 'tmsi' in kw:
            tmsi = kw['tmsi']
            if tmsi in self.TMSI:
                return self.UE[self.TMSI[tmsi]]
            elif '*' in self.ConfigUE:
                # creating a UEd instance which will request IMSI
                ued = UEd(self, '', tmsi=tmsi, config=self.ConfigUE['*'])
                self._UEpre[tmsi] = ued
                return ued
        elif 'ptmsi' in kw:
            ptmsi = kw['ptmsi']
            if ptmsi in self.PTMSI:
                return self.UE[self.PTMSI[ptmsi]]
            elif '*' in self.ConfigUE:
                # creating a UEd instance which will request IMSI
                ued = UEd(self, '', ptmsi=ptmsi, config=self.ConfigUE['*'])
                self._UEpre[ptmsi] = ued
                return ued
        return None
    
    def is_imsi_allowed(self, imsi):
        if imsi in self.ConfigUE:
            # preconfigured UE
            return True
        elif re.match(self.UE_ATTACH_FILTER, imsi):
            # non-preconfigured UE
            return True
        else:
            return False
    
    def clean_ue_proc(self):
        pass

