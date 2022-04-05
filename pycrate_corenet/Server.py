# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2017. Benoit Michau. ANSSI.
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
# * File Name : pycrate_corenet/Server.py
# * Created : 2017-06-28
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

#------------------------------------------------------------------------------#
# This is the main corenet server
# 
# It serves connection to:
# - Home-NodeB over HNBAP and RUA / RANAP
# - eNodeB and Home-eNodeB over S1AP
# - gNodeB over NGAP
# 
# It handles signalling trafic for UE
# and connects them to specific service handler (SMS, GTPU, ...)
#------------------------------------------------------------------------------#

from .utils      import *
from .HdlrHNB    import HNBd
from .HdlrENB    import ENBd
from .HdlrGNB    import GNBd
from .HdlrUE     import UEd
from .ServerAuC  import AuC
from .ServerGTPU import ARPd, GTPUd, BLACKHOLE_LAN, BLACKHOLE_WAN
#
from .ProcCNHnbap   import HNBAPErrorIndGW
from .ProcCNRua     import RUAErrorInd
from .ProcCNS1ap    import S1APErrorIndNonUECN
from .ProcCNNgap    import NGAPErrorIndNonUECN


# to log all the SCTP socket send() / recv() calls
DEBUG_SK = False


class CorenetServer(object):
    """Complete control-plane and user-plane server to handle:
    - Home-NodeB, over HNBAP and RUA / RANAP
    - eNodeB, over S1AP
    - gNodeB, over NGAP
    And UE connecting through them for data connection (over GTP-U) and SMS
    """
    
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
    # for extended socket buffering,
    # configure /proc/sys/net/core/rmem_max and /proc/sys/net/core/wmem_max accordingly
    #SERVER_BUFLEN = 1048576
    #
    SERVER_MAXCLI = 16
    #
    # HNBAP server
    SERVER_HNB = {'INET'  : socket.AF_INET,
                  'IP'    : '10.1.1.1',
                  'port'  : 29169,
                  'MAXCLI': SERVER_MAXCLI,
                  'errclo': True,
                  'GTPU'  : '10.1.1.1'}
    #SERVER_HNB = {} # disabling HNB server
    #
    # S1AP server
    SERVER_ENB = {'INET'  : socket.AF_INET,
                  'IP'    : '10.2.1.1',
                  'port'  : 36412,
                  'MAXCLI': SERVER_MAXCLI,
                  'errclo': True,
                  'GTPU'  : '10.2.1.1'}
    #SERVER_ENB = {} # disabling S1AP server
    #
    # NGAP Server
    SERVER_GNB = {'INET'  : socket.AF_INET,
                  'IP'    : '10.3.1.1',
                  'port'  : 38412,
                  'MAXCLI': SERVER_MAXCLI,
                  'errclo': True,
                  'GTPU'  : '10.3.1.1'}
    #SERVER_GNB = {} # disable NGAP Server
    #
    # Server scheduler resolution:
    # This is the timeout on the main select() loop.
    SCHED_RES = 0.1
    # This is the resolution (in sec) for the Server to start a thread that 
    # checks the list of registered UE, and checks for ongoing NAS procedures 
    # potentially in timeout.
    # If set to 0, no check is made (so, NAS procedures can stall)
    # It is useless to make it lower than the SCHED_RES.
    SCHED_UE_TO = 0.5
    
    #--------------------------------------------------------------------------#
    # corenet service handlers
    #--------------------------------------------------------------------------#
    # These are references to services handlers
    #
    # Authentication Centre
    AUCd  = AuC
    # GTPU trafic forwarder
    GTPUd = GTPUd
    # SMS center
    SMSd  = None
    
    #--------------------------------------------------------------------------#
    # corenet global config parameters
    #--------------------------------------------------------------------------#
    #
    # main PLMN served
    PLMN = '00101'
    
    
    ### AMF-related config
    #
    # AMF ID for each served PLMN
    # PLMN (str): AMF ID 3-tuple (RegionID uint8, SetID uint10, Pointer uint6)
    AMF_GUAMI = {
        PLMN: (0x01, 0x001, 0x00),
        }
    #
    # arbitrary dict of indexed slices identifiers
    # S-NSSAI is at least an SST (uint8) and eventually an SD (uint24)
    AMF_SNSSAI = {
        0  : (0x00, ), # default S-NSSAI
        1  : (0x01, ),
        2  : (0x02, ),
        21 : (0x02, 0x000001),
        }
    # list of slice supported for each served PLMN
    AMF_PLMNSupp = {
        PLMN: [AMF_SNSSAI[0]],
        #$plmn1: [AMF_SNSSAI[1]],
        #$plmn2: [AMF_SNSSAI[2], AMF_SNSSAI[21]],
        }
    #
    # NG connection AMF parameters
    ConfigNG    = {
        'AMFName'            : 'CorenetAMF',
        'RelativeAMFCapacity': 10,
        #'UERetentionInformation': 'ues-retained',
        }
    
    
    ### IuCS, IuPS and S1 common parameters
    #
    # equivalent PLMNs served, used for Iu and S1 interface
    # None or list of PLMNs ['30124', '763326', ...]
    EQUIV_PLMN = None
    #
    # emergency number lists
    # None or list of 2-tuple [(number_category, number), ...]
    # number_category is a set of strings: 'Police', 'Ambulance', 'Fire', 'Marine', 'Mountain'
    # number is a digits string
    # e.g.
    #CorenetServer.EMERG_NUMS = [
    #    ({'Police', 'Ambulance', 'Fire'}, '112112'),
    #    ({'Marine', 'Mountain'}, '112113')]
    EMERG_NUMS = None
    
    
    ### MME-related config
    #
    # MME GroupID and Code
    MME_GID  = 1
    MME_CODE = 1
    #
    # S1 connection MME parameters
    ConfigS1    = {
        'MMEname': 'CorenetMME',
        'ServedGUMMEIs' : [
            {'servedPLMNs'   : [plmn_str_to_buf(PLMN)],
             'servedGroupIDs': [uint_to_bytes(MME_GID, 16)],
             'servedMMECs'   : [uint_to_bytes(MME_CODE, 8)]}
            ],
        'RelativeMMECapacity': 10,
        'EquivPLMNList' : EQUIV_PLMN,
        'EmergNumList'  : EMERG_NUMS,
        }
    
    
    ### MSC/VLR/SGSN-related config
    #
    # HNBAP connection GW parameters (keep it empty)
    ConfigHNBAP = {}
    # RUA connection GW parameters (keep it empty)
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
    # HNB, ENB and GNB parameters
    #--------------------------------------------------------------------------#
    #
    # Connection from RAN equipments:
    # Home-NodeB, eNodeB and gNodeB indexed by their global ID
    # (PLMN, CellId) for home-NodeB and eNodeB
    # (PLMN, CellType, CellId) for gNodeB
    # the RAN dict can be initialized with {(PLMN, *Cell*): None} here
    # this provides a whitelist of allowed basestations.
    RAN = {}
    #
    # Otherwise, this is a flag to allow any RAN equipment to connect the server
    # in case its PLMN is in the RAN_ALLOWED_PLMN list.
    # If enabled, RAN dict will be populated at runtime
    # If disabled, RAN keys (PLMN, *Cell*) needs to be setup by configuration (see above)
    RAN_CONNECT_ANY = True
    #
    # This is the list of accepted PLMN for RAN equipment connecting, 
    # when RAN_CONNECT_ANY is enabled
    RAN_ALLOWED_PLMN = [PLMN]
    #
    # lookup dict to get the set of RAN ids (PLMN, CellId) that serves a given
    # LAI, RAI and TAI
    LAI = {}
    RAI = {}
    TAI = {}
    
    #--------------------------------------------------------------------------#
    # UE parameters
    #--------------------------------------------------------------------------#
    #
    # UE configuration parameters
    ConfigUE = {
        # $IMSI: {'PDN'   : [($APN -str-, $PDNType -1..3-, $IPAddr -str-, ...), ...], 
        #         'MSISDN': $phone_num -str-,
        #         'USIM'  : $milenage_supported -bool-}
        # PDP type: 0:PPP, 1:IPv4, 2: IPv6 /64 local if, 3: IPv4v6 (-> 1 IPv4 + 1 IPv6 local if)
        # PDN type: 1:IPv4, 2:IPv6 /64 local if, 3:IPv4v6 (-> 1 IPv4 + 1 IPv6 local if)
        # PDU type: TODO
        '*': {'PDP'   : [('*', 1, '192.168.1.199')],
              'PDN'   : [('*', 1, '192.168.1.199')],
              'PDU'   : [], # TODO
              'MSISDN': '0123456789',
              'USIM'  : True
              },
        '001011000000001': {'PDP'   : [('*', 3, '192.168.1.201', '0:1:0:c9'),
                                       ('corenet', 1, '192.168.1.201')],
                            'PDN'   : [('*', 3, '192.168.1.201', '0:1:0:c9'),
                                       ('corenet', 1, '192.168.1.201')],
                            'PDU'   : [], # TODO
                            'MSISDN': '100001',
                            'USIM'  : True
                            },
        '001011000000002': {'PDP'   : [('*', 3, '192.168.1.202', '0:1:0:ca'),
                                       ('corenet', 1, '192.168.1.202')],
                            'PDN'   : [('*', 3, '192.168.1.202', '0:1:0:ca'),
                                       ('corenet', 1, '192.168.1.202')],
                            'PDU'   : [], # TODO
                            'MSISDN': '100002',
                            'USIM'  : True
                            }
        }
    #
    # Packet Data Protocol config for 2G-3G PS domain, per APN
    ConfigPDP = {
        '*': {
            'DNS': ((1, '8.8.8.8'), # Google DNS servers
                    (1, '8.8.4.4'),
                    (2, '2001:4860:4860::8888'),
                    (2, '2001:4860:4860::8844')),
            'MTU': (None, None),
            },
        'corenet': {
            'DNS': ((1, '8.8.8.8'),
                    (1, '8.8.4.4')),
            'MTU': (None, None),
            },
        }
    #
    # Packet Data Network config for EPC, per APN
    ConfigPDN = {
        '*': {
            'QCI': 9,
            'DNS': ((1, '8.8.8.8'), # Google DNS servers
                    (1, '8.8.4.4'),
                    (2, '2001:4860:4860::8888'),
                    (2, '2001:4860:4860::8844')),
            'MTU': (None, None),
            },
        'corenet': {
            'QCI': 9,
            'DNS': ((1, '8.8.8.8'),
                    (1, '8.8.4.4')),
            'MTU': (None, None),
            },
        }
    #
    # PDU Sessions config for 5GS, per DNN
    ConfigPDU = {
        '*': {
            # TODO
            },
        'corenet': {
            # TODO
            },
        }
    #
    # UE, indexed by IMSI, and their UEd handler instance
    UE = {}
    # UE, indexed by TMSI when the IMSI is unknown (at attachment), 
    # and their UEd handler instance are set in ._UEpre, created at init
    #
    # TMSI / P-TMSI / M-TMSI / 5G-TMSI to IMSI conversion
    TMSI   = {}
    PTMSI  = {}
    MTMSI  = {}
    FGTMSI = {}
    #
    # This is a filter which enables the potential attachment of non-preconfigured 
    # UE to the CorenetServer
    # WNG: for IMSI that are not preconfigured (no Ki in the AuC database),
    # further UE-related procedure will fail because of missing crypto material.
    # When an non-preconfigured UE attaches the CorenetServer, ConfigUE['*'] is 
    # used to provide a default config and need to be defined.
    # use UE_ATTACH_FILTER = None to disable this permissive filter.
    UE_ATTACH_FILTER = '^00101'
    
    #--------------------------------------------------------------------------#
    # logging and init methods
    #--------------------------------------------------------------------------#
    
    def _log(self, logtype, msg):
        """Server logging facility
        
        DEBUG logtype: 'ERR', 'WNG', 'INF', 'DBG'
        TRACE logtype: 'TRACE_SK_[UL|DL]',
                       'TRACE_ASN_[HNBAP|RUA|S1AP|NGAP]_[UL|DL]',
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
            self._server = threadit(self.start, serving=serving)
        else:
            self.start(serving=serving)
    
    #--------------------------------------------------------------------------#
    # SCTP socket server
    #--------------------------------------------------------------------------#
    
    def start(self, serving=True):
        #
        if DEBUG_SK:
            self._skc   = []
        # LUT for connected SCTP client and ENBId / HNBId
        self.SCTPCli    = {}
        #
        # start SCTP servers, bind() and listen()
        self._start_server()
        #
        # init the dict for storing UE with unknown IMSI at attachment
        self._UEpre = {}
        # set the LUT for MSISDN to IMSI translation
        self.MSISDN = {}
        for imsi, cfgue in self.ConfigUE.items():
            self.MSISDN[cfgue['MSISDN']] = imsi
        # init the UE procedure cleaner holder
        # (with a dummy thread, which will be overridden at runtime)
        self._clean_ue_proc = threadit( lambda: 1 )
        #
        # clear LAI, RAI, TAI dict
        self.LAI.clear()
        self.RAI.clear()
        self.TAI.clear()
        #
        # initialize GTP TEID UL counter
        self._GTP_TEID_UL = randint(1, 200000)
        #
        # start sub-servers
        if self.AUCd:
            self.AUCd  = self.__class__.AUCd()
        if self.GTPUd:
            self.GTPUd = self.__class__.GTPUd()
        if self.SMSd:
            self.SMSd  = self.__class__.SMSd()
            self.SMSd.Server = self
        #
        if serving:
            # serve connections
            self._serve()
            # self._running has been set to False, main loop exited
            self._log('INF', 'SCTP server stopped')
    
    def is_running(self):
        return self._running
    
    def _start_server(self):
        self.SCTPServ = []
        for (cfg, attr) in ((self.SERVER_HNB, '_sk_hnb'),
                            (self.SERVER_ENB, '_sk_enb'),
                            (self.SERVER_GNB, '_sk_gnb')):
            if 'INET' not in cfg or 'IP' not in cfg \
            or 'port' not in cfg or 'MAXCLI' not in cfg:
                setattr(self, attr, None)
                continue
            #
            try:
                sk   = sctp.sctpsocket_tcp(cfg['INET'])
                addr = (cfg['IP'], cfg['port'])
                srv  = attr[-3:].upper()
                self.sctp_set_events(sk)
            except Exception as err:
                raise(CorenetErr('cannot create SCTP socket: %s' % err))
            try:
                sk.bind(addr)
            except Exception as err:
                raise(CorenetErr('cannot bind SCTP socket on addr %r: %s' % (addr, err)))
            try:
                sk.listen(cfg['MAXCLI'])
            except Exception as err:
                raise(CorenetErr('cannot listen to SCTP connection: {1}'.format(err)))
            #
            self._log('INF', 'SCTP %s server started on address %r' % (srv, addr))
            setattr(self, attr, sk)
            self.SCTPServ.append(sk)
        #
        self.SCTPServ = tuple(self.SCTPServ)
    
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
                if sk == self._sk_gnb:
                    # new gNodeB SCTP client (NGSetupRequest)
                    self.handle_new_gnb()
                elif sk == self._sk_enb:
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
            if self.SCHED_UE_TO and time() - T0 > self.SCHED_UE_TO and \
            not self._clean_ue_proc.isAlive():
                # select() timeout or more than `SCHED_RES' seconds since 
                # last timeout
                self._clean_ue_proc = threadit(self.clean_ue_proc)
                T0 = time()
    
    def stop(self):
        self._running = False
        asn_ngap_release()
        asn_s1ap_release()
        asn_hnbap_release()
        asn_rua_release()
        asn_ranap_release()
        sleep(self.SCHED_RES + 0.01)
        if self._sk_hnb is not None:
            self._sk_hnb.close()
        if self._sk_enb is not None:
            self._sk_enb.close()
        if self._sk_gnb is not None:
            self._sk_gnb.close()
        self._clean_ue_proc.join()
        #
        # disconnect all RAN clients
        for cli in self.SCTPCli:
            cli.close()
            self.RAN[self.SCTPCli[cli]].disconnect()
        self.SCTPCli.clear()
        #
        # stop sub-servers
        try:
            self.AUCd.stop()
            self.GTPUd.stop()
            self.SMSd.stop()
        except Exception:
            pass
    
    def sctp_handle_notif(self, sk, notif):
        self._log('DBG', 'SCTP notification: type %i, flags %i' % (notif.type, notif.flags))
        # TODO
    
    def sctp_set_events(self, sk):
        # configure the SCTP socket to receive adaptation layer and stream id
        # indications in sctp_recv() notification
        sk.events.data_io          = True
        sk.events.adaptation_layer = True
        #sk.events.association      = True
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
        except ConnectionError as err:
            # something went bad with the endpoint
            self._log('ERR', 'sctp_recv() failed, err: {0}'.format(err))
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
                # TODO: store all fragments from the peer until the next msg with FLAG_EOR
                return None, None
        return buf, notif
    
    def _rem_sk(self, sk):
        # close socket
        sk.close()
        # select RAN client
        cli = self.RAN[self.SCTPCli[sk]]
        if isinstance(cli, HNBd):
            self._log('DBG', 'HNB %r closed connection' % (cli.ID,))            
            # remove from the Server location tables
            if cli.Config:
                self._unset_hnb_loc(cli)
        elif isinstance(cli, ENBd):
            self._log('DBG', 'eNB %r closed connection' % (cli.ID,))
            # remove from the Server location tables
            if cli.Config:
                self._unset_enb_loc(cli)
        elif isinstance(cli, GNBd):
            self._log('DBG', 'gNB %s closed connection' % (cli.ID,))
            # remove from the Server location tables
            if cli.Config:
                self._unset_gnb_loc(cli)
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
            ppid = htonl(ppid)
        #if stream:
        #    stream = htonl(stream)
        ret = 0
        try:
            ret = sk.sctp_send(buf, ppid=ppid, stream=stream)
        except Exception as err:
            self._log('ERR', 'cannot send buf to SCTP client at address %r' % (sk.getpeername(), ))
            if DEBUG_SK:
                self._skc.append( ('send', time(), buf, ppid, stream, err) )
        else:
            if DEBUG_SK:
                self._skc.append( ('send', time(), buf, ppid, stream) )
        return ret
    
    def handle_stream_msg(self, sk):
        buf, notif = self._read_sk(sk)
        if not buf:
            # WNG: it may be required to handle SCTP notifications, at some point...
            return
        # getting SCTP ppid, stream id and eNB/HNB handler
        ppid, sid, ranid = ntohl(notif.ppid), notif.stream, self.SCTPCli[sk]
        ran = self.RAN[ranid]
        #
        if ppid == SCTP_PPID_HNBAP:
            assert( isinstance(ran, HNBd) )
            hnb = ran
            if not asn_hnbap_acquire():
                hnb._log('ERR', 'unable to acquire the HNBAP module')
                return
            try:
                PDU_HNBAP.from_aper(buf)
            except Exception:
                asn_hnbap_release()
                hnb._log('WNG', 'invalid HNBAP PDU transfer-syntax: %s'\
                         % hexlify(buf).decode('ascii'))
                Err = hnb.init_hnbap_proc(HNBAPErrorIndGW,
                                          Cause=('protocol', 'transfer-syntax-error'))
                Err.recv(buf)
                pdu_tx = Err.send()
            else:
                pdu_rx = PDU_HNBAP()
                if hnb.TRACE_ASN_HNBAP:
                    hnb._log('TRACE_ASN_HNBAP_UL', PDU_HNBAP.to_asn1())
                asn_hnbap_release()
                if not isinstance(pdu_rx[1], dict):
                    # invalid PDU, undefined extension
                    hnb._log('WNG', 'invalid HNBAP PDU transfer-syntax: %s'\
                             % hexlify(buf).decode('ascii'))
                    Err = hnb.init_hnbap_proc(HNBAPErrorIndGW,
                                              Cause=('protocol', 'transfer-syntax-error'))
                    Err.recv(pdu_rx)
                    pdu_tx = Err.send()
                else:
                    pdu_tx = hnb.process_hnbap_pdu(pdu_rx)
            for pdu in pdu_tx:
                self.send_hnbap_pdu(hnb, pdu)
        #
        elif ppid == SCTP_PPID_RUA:
            assert( isinstance(ran, HNBd) )
            hnb = ran
            if not asn_rua_acquire():
                hnb._log('ERR', 'unable to acquire the RUA module')
                return
            try:
                PDU_RUA.from_aper(buf)
            except Exception:
                asn_rua_release()
                self._log('WNG', 'invalid RUA PDU transfer-syntax: %s'\
                          % hexlify(buf).decode('ascii'))
                Err = hnb.init_rua_proc(RUAErrorInd,
                                        Cause=('protocol', 'transfer-syntax-error'))
                Err.recv(buf)
                pdu_tx = Err.send()
            else:
                pdu_rx = PDU_RUA()
                if hnb.TRACE_ASN_RUA:
                    hnb._log('TRACE_ASN_RUA_UL', PDU_HNBAP.to_asn1())
                asn_rua_release()
                if not isinstance(pdu_rx[1], dict):
                    # invalid PDU, undefined extension
                    self._log('WNG', 'invalid RUA PDU transfer-syntax: %s'\
                              % hexlify(buf).decode('ascii'))
                    Err = hnb.init_rua_proc(RUAErrorInd,
                                            Cause=('protocol', 'transfer-syntax-error'))
                    Err.recv(pdu_rx)
                    pdu_tx = Err.send()
                else:
                    pdu_tx = hnb.process_rua_pdu(pdu_rx)
            for pdu in pdu_tx:
                self.send_rua_pdu(hnb, pdu)
        #
        elif ppid == SCTP_PPID_S1AP:
            assert( isinstance(ran, ENBd) )
            enb = ran
            if not asn_s1ap_acquire():
                enb._log('ERR', 'unable to acquire the S1AP module')
                return
            try:
                PDU_S1AP.from_aper(buf)
            except Exception:
                asn_s1ap_release()
                enb._log('WNG', 'invalid S1AP PDU transfer-syntax: %s'\
                         % hexlify(buf).decode('ascii'))
                Err = enb.init_s1ap_proc(S1APErrorIndNonUECN,
                                         Cause=('protocol', 'transfer-syntax-error'))
                Err.recv(buf)
                pdu_tx = Err.send()
            else:
                pdu_rx = PDU_S1AP()
                if enb.TRACE_ASN_S1AP:
                    enb._log('TRACE_ASN_S1AP_UL', PDU_S1AP.to_asn1())
                asn_s1ap_release()
                if not isinstance(pdu_rx[1], dict):
                    # invalid PDU, undefined extension
                    enb._log('WNG', 'invalid S1AP PDU transfer-syntax: %s'\
                             % hexlify(buf).decode('ascii'))
                    Err = enb.init_s1ap_proc(S1APErrorIndNonUECN,
                                             Cause=('protocol', 'transfer-syntax-error'))
                    Err.recv(pdu_rx)
                    pdu_tx = Err.send()
                else:
                    if sid == enb.SKSid:
                        # non-UE-associated signalling
                        pdu_tx = enb.process_s1ap_pdu(pdu_rx)
                    else:
                        # UE-associated signalling
                        pdu_tx = enb.process_s1ap_ue_pdu(pdu_rx, sid)
            for pdu in pdu_tx:
                self.send_s1ap_pdu(enb, pdu, sid)
        #
        elif ppid == SCTP_PPID_NGAP:
            assert( isinstance(ran, GNBd) )
            gnb = ran
            if not asn_ngap_acquire():
                gnb._log('ERR', 'unable to acquire the NGAP module')
                return
            try:
                PDU_NGAP.from_aper(buf)
            except Exception:
                asn_ngap_release()
                gnb._log('WNG', 'invalid NGAP PDU transfer-syntax: %s'\
                         % hexlify(buf).decode('ascii'))
                Err = gnb.init_ngap_proc(NGAPErrorIndNonUECN,
                                         Cause=('protocol', 'transfer-syntax-error'))
                Err.recv(buf)
                pdu_tx = Err.send()
            else:
                pdu_rx = PDU_NGAP()
                if gnb.TRACE_ASN_NGAP:
                    gnb._log('TRACE_ASN_NGAP_UL', PDU_NGAP.to_asn1())
                asn_ngap_release()
                if not isinstance(pdu_rx[1], dict):
                    # invalid PDU, undefined extension
                    gnb._log('WNG', 'invalid NGAP PDU transfer-syntax: %s'\
                             % hexlify(buf).decode('ascii'))
                    Err = gnb.init_ngap_proc(NGAPErrorIndNonUECN,
                                             Cause=('protocol', 'transfer-syntax-error'))
                    Err.recv(pdu_rx)
                    pdu_tx = Err.send()
                else:
                    if sid == gnb.SKSid:
                        # non-UE-associated signalling
                        pdu_tx = gnb.process_ngap_pdu(pdu_rx)
                    else:
                        # UE-associated signalling
                        pdu_tx = gnb.process_ngap_ue_pdu(pdu_rx, sid)
            for pdu in pdu_tx:
                self.send_ngap_pdu(gnb, pdu, sid)
        #
        else:
            self._log('ERR', 'invalid SCTP PPID, %i' % ppid)
            if self.SERVER_HNB['errclo']:
                self._rem_sk(sk)
            return
    
    def send_hnbap_pdu(self, hnb, pdu):
        if not asn_hnbap_acquire():
            hnb._log('ERR', 'unable to acquire the HNBAP module')
            return
        PDU_HNBAP.set_val(pdu)
        if hnb.TRACE_ASN_HNBAP:
            hnb._log('TRACE_ASN_HNBAP_DL', PDU_HNBAP.to_asn1())
        buf = PDU_HNBAP.to_aper()
        asn_hnbap_release()
        return self._write_sk(hnb.SK, buf, ppid=SCTP_PPID_HNBAP)
    
    def send_rua_pdu(self, hnb, pdu):
        if not asn_rua_acquire():
            hnb._log('ERR', 'unable to acquire the RUA module')
            return
        PDU_RUA.set_val(pdu)
        if hnb.TRACE_ASN_RUA:
            hnb._log('TRACE_ASN_RUA_DL', PDU_RUA.to_asn1())
        buf = PDU_RUA.to_aper()
        asn_rua_release()
        return self._write_sk(hnb.SK, buf, ppid=SCTP_PPID_RUA)
    
    def send_s1ap_pdu(self, enb, pdu, sid):
        if not asn_s1ap_acquire():
            enb._log('ERR', 'unable to acquire the S1AP module')
            return
        PDU_S1AP.set_val(pdu)
        if enb.TRACE_ASN_S1AP:
            enb._log('TRACE_ASN_S1AP_DL', PDU_S1AP.to_asn1())
        buf = PDU_S1AP.to_aper()
        asn_s1ap_release()
        return self._write_sk(enb.SK, buf, ppid=SCTP_PPID_S1AP, stream=sid)
    
    def send_ngap_pdu(self, gnb, pdu, sid):
        if not asn_ngap_acquire():
            gnb._log('ERR', 'unable to acquire the NGAP module')
            return
        PDU_NGAP.set_val(pdu)
        if gnb.TRACE_ASN_NGAP:
            gnb._log('TRACE_ASN_NGAP_DL', PDU_NGAP.to_asn1())
        buf = PDU_NGAP.to_aper()
        asn_ngap_release()
        return self._write_sk(gnb.SK, buf, ppid=SCTP_PPID_NGAP, stream=sid)
    
    #--------------------------------------------------------------------------#
    # eNodeB connection (4G)
    #--------------------------------------------------------------------------#
    
    def _parse_s1setup(self, pdu):
        if pdu[0] != 'initiatingMessage' or pdu[1]['procedureCode'] != 17:
            # not initiating / S1Setup
            self._log('WNG', 'invalid S1AP PDU for setting up the eNB S1AP link')
            return
        #
        pIEs, plmn, cellid = pdu[1]['value'][1], None, None
        IEs = pIEs['protocolIEs']
        if 'protocolExtensions' in pIEs:
            Exts = pIEs['protocolExtensions']
        else:
            Exts = []
        for ie in IEs:
            if ie['id'] == 59:
                # Global-ENB-ID
                globenbid = ie['value'][1]
                plmn      = globenbid['pLMNidentity']
                cellid    = globenbid['eNB-ID'][1] # both macro / home eNB-ID are BIT STRING
                break
        if plmn is None or cellid is None:
            self._log('WNG', 'invalid S1AP PDU for setting up the eNB S1AP link: '\
                      'missing PLMN and CellID')
            return
        # decode PLMN and CellID
        try:
            PLMN   = plmn_buf_to_str(plmn)
            CellID = cellid_bstr_to_str(cellid)
            return PLMN, CellID
        except Exception:
            return None
    
    def _send_s1setuprej(self, sk, cause):
        IEs = [{'criticality': 'ignore',
                'id': 2, # id-Cause
                'value': (('S1AP-IEs', 'Cause'), cause)}]
        pdu = ('unsuccessfulOutcome',
               {'criticality': 'ignore',
                'procedureCode': 17,
                'value': (('S1AP-PDU-Contents', 'S1SetupFailure'),
                          {'protocolIEs' : IEs})})
        if not asn_s1ap_acquire():
            self._log('ERR', 'unable to acquire the S1AP module')
        else:
            PDU_S1AP.set_val(pdu)
            if ENBd.TRACE_ASN_S1AP:
                self._log('TRACE_ASN_S1AP_DL', PDU_S1AP.to_asn1())
            self._write_sk(sk, PDU_S1AP.to_aper(), ppid=SCTP_PPID_S1AP, stream=0)
            asn_s1ap_release()
        if self.SERVER_ENB['errclo']:
            sk.close()
    
    def handle_new_enb(self):
        sk, addr = self._sk_enb.accept()
        self._log('DBG', 'New eNB client from address %r' % (addr, ))
        #
        buf, notif = self._read_sk(sk)
        if not buf:
            # WNG: maybe required to handle SCTP notification, at some point
            return
        # verifying SCTP Payload Protocol ID and setting stream ID for 
        # non-UE-associated trafic
        ppid, sid = ntohl(notif.ppid), notif.stream
        if ppid != SCTP_PPID_S1AP:
            self._log('ERR', 'invalid S1AP PPID, %i' % ppid)
            if self.SERVER_ENB['errclo']:
                sk.close()
            return
        #
        if not asn_s1ap_acquire():
            self._log('ERR', 'unable to acquire the S1AP module')
            return
        try:
            PDU_S1AP.from_aper(buf)
        except Exception:
            self._log('WNG', 'invalid S1AP PDU transfer-syntax: %s'\
                      % hexlify(buf).decode('ascii'))
            asn_s1ap_release()
            # return nothing, no need to bother
            return
        if ENBd.TRACE_ASN_S1AP:
            self._log('TRACE_ASN_S1AP_UL', PDU_S1AP.to_asn1())
        pdu_rx = PDU_S1AP()
        asn_s1ap_release()
        #
        ENBId = self._parse_s1setup(pdu_rx)
        if ENBId is None:
            # send S1SetupReject
            self._send_s1setuprej(sk, cause=('protocol', 'abstract-syntax-error-reject'))
            return
        elif ENBId not in self.RAN:
            if not self.RAN_CONNECT_ANY:
                self._log('ERR', 'eNB %r not allowed to connect' % (ENBId, ))
                # send S1SetupReject
                self._send_s1setuprej(sk, cause=('radioNetwork', 'unspecified'))
                return
            elif ENBId[0] not in self.RAN_ALLOWED_PLMN:
                self._log('ERR', 'eNB %r not allowed to connect, bad PLMN' % (ENBId, ))
                self._send_s1setuprej(sk, cause=('radioNetwork', 'unspecified'))
                return
            else:
                # creating an entry for this eNB
                enb = ENBd(self, sk, sid)
                self.RAN[ENBId] = enb
        else:
            if self.RAN[ENBId] is None:
                # eNB allowed, but not yet connected
                enb = ENBd(self, sk, sid)
                self.RAN[ENBId] = enb
            elif not self.RAN[ENBId].is_connected():
                # eNB already connected and disconnected in the past
                enb = self.RAN[ENBId]
                enb.__init__(self, sk, sid)
            else:
                # eNB already connected
                self._log('ERR', 'eNB %r already connected from address %r'\
                          % (ENBId, self.RAN[ENBId].SK.getpeername()))
                if self.SERVER_ENB['errclo']:
                    sk.close()
                return
        #
        # process the initial PDU
        pdu_tx = enb.process_s1ap_pdu(pdu_rx)
        # keep track of the client
        self.SCTPCli[sk] = ENBId
        # add the enb TAI to the Server location tables
        if enb.Config:
            self._set_enb_loc(enb)
        #
        # send available PDU(s) back
        if not asn_s1ap_acquire():
           enb._log('ERR', 'unable to acquire the S1AP module')
           return
        for pdu in pdu_tx:
            PDU_S1AP.set_val(pdu)
            if ENBd.TRACE_ASN_S1AP:
                enb._log('TRACE_ASN_S1AP_DL', PDU_S1AP.to_asn1())
            self._write_sk(sk, PDU_S1AP.to_aper(), ppid=SCTP_PPID_S1AP, stream=sid)
        asn_s1ap_release()
    
    def _set_enb_loc(self, enb):
        for tai in enb.Config['TAIs']:
            if tai in self.TAI:
                assert( enb.ID not in self.TAI[tai] )
                self.TAI[tai].add( enb.ID )
            else:
                self.TAI[tai] = set( (enb.ID, ) )
    
    def _unset_enb_loc(self, enb):
        for tai in enb.Config['TAIs']:
            try:
                self.TAI[tai].remove(enb.ID)
            except Exception:
                self._log('ERR', 'RAN node %r not referenced into the TAI table' % (enb.ID,))
    
    #--------------------------------------------------------------------------#
    # gNodeB connection (5G)
    #--------------------------------------------------------------------------#
    
    def _parse_ngsetup(self, pdu):
        if pdu[0] != 'initiatingMessage' or pdu[1]['procedureCode'] != 21:
            # not initiating / NGSetup
            self._log('WNG', 'invalid NGAP PDU for setting up the gNB NGAP link')
            return
        #
        pIEs, plmn, ranid = pdu[1]['value'][1], None, None
        IEs = pIEs['protocolIEs']
        if 'protocolExtensions' in pIEs:
            Exts = pIEs['protocolExtensions']
        else:
            Exts = []
        for ie in IEs:
            if ie['id'] == 27:
                # GlobalRANNodeID:
                # PLMN,
                # ID type (gNB-ID, macroNgENB-ID, shortMacroNgENB-ID, longMacroNgENB-ID or n3IWF-ID),
                # ID bit-string value 
                ranid = globranid_to_hum(ie['value'][1])
                break
        if ranid is None:
            self._log('WNG', 'invalid NGAP PDU for setting up the gNB NGAP link: '\
                      'missing PLMN and RAN-ID')
            return
        return ranid
    
    def _send_ngsetuprej(self, sk, cause):
        IEs = [{'criticality': 'ignore',
                'id': 15, # id-Cause
                'value': (('NGAP-IEs', 'Cause'), cause)}]
        pdu = ('unsuccessfulOutcome',
               {'criticality': 'ignore',
                'procedureCode': 21,
                'value': (('NGAP-PDU-Contents', 'NGSetupFailure'),
                          {'protocolIEs' : IEs})})
        if not asn_ngap_acquire():
            self._log('ERR', 'unable to acquire the NGAP module')
        else:
            PDU_NGAP.set_val(pdu)
            if GNBd.TRACE_ASN_NGAP:
                self._log('TRACE_ASN_NGAP_DL', PDU_NGAP.to_asn1())
            self._write_sk(sk, PDU_NGAP.to_aper(), ppid=SCTP_PPID_NGAP, stream=0)
            asn_ngap_release()
        if self.SERVER_GNB['errclo']:
            sk.close()
    
    def handle_new_gnb(self):
        sk, addr = self._sk_gnb.accept()
        self._log('DBG', 'New gNB client from address %r' % (addr, ))
        #
        buf, notif = self._read_sk(sk)
        if not buf:
            # WNG: maybe required to handle SCTP notification, at some point
            return
        # verifying SCTP Payload Protocol ID and setting stream ID for 
        # non-UE-associated trafic
        ppid, sid = ntohl(notif.ppid), notif.stream
        if ppid != SCTP_PPID_NGAP:
            self._log('ERR', 'invalid NGAP PPID, %i' % ppid)
            if self.SERVER_GNB['errclo']:
                sk.close()
            return
        #
        if not asn_ngap_acquire():
            self._log('ERR', 'unable to acquire the NGAP module')
            return
        try:
            PDU_NGAP.from_aper(buf)
        except Exception:
            self._log('WNG', 'invalid NGAP PDU transfer-syntax: %s'\
                      % hexlify(buf).decode('ascii'))
            asn_ngap_release()
            # return nothing, no need to bother
            return
        if GNBd.TRACE_ASN_NGAP:
            self._log('TRACE_ASN_NGAP_UL', PDU_NGAP.to_asn1())
        pdu_rx = PDU_NGAP()
        asn_ngap_release()
        #
        GNBId = self._parse_ngsetup(pdu_rx)
        if GNBId is None:
            # send NGSetupReject
            self._send_ngsetuprej(sk, cause=('protocol', 'abstract-syntax-error-reject'))
            return
        elif GNBId not in self.RAN:
            if not self.RAN_CONNECT_ANY:
                self._log('ERR', 'gNB %r not allowed to connect' % (GNBId,))
                # send NGSetupReject
                self._send_ngsetuprej(sk, cause=('radioNetwork', 'unspecified'))
                return
            elif GNBId[0] not in self.RAN_ALLOWED_PLMN:
                self._log('ERR', 'gNB %r not allowed to connect, bad PLMN' % (GNBId,))
                self._send_ngsetuprej(sk, cause=('radioNetwork', 'unspecified'))
                return
            else:
                # creating an entry for this gNB
                gnb = GNBd(self, sk, sid)
                self.RAN[GNBId] = gnb
        else:
            if self.RAN[GNBId] is None:
                # gNB allowed, but not yet connected
                gnb = GNBd(self, sk, sid)
                self.RAN[GNBId] = gnb
            elif not self.RAN[GNBId].is_connected():
                # gNB already connected and disconnected in the past
                gnb = self.RAN[GNBId]
                gnb.__init__(self, sk, sid)
            else:
                # gNB already connected
                self._log('ERR', 'gNB %r already connected from address %r'\
                          % (GNBId, self.RAN[GNBId].SK.getpeername()))
                if self.SERVER_GNB['errclo']:
                    sk.close()
                return
        #
        # process the initial PDU
        pdu_tx = gnb.process_ngap_pdu(pdu_rx)
        # keep track of the client
        self.SCTPCli[sk] = GNBId
        # add the gnb TAI to the Server location tables
        if gnb.Config:
            self._set_gnb_loc(gnb)
        #
        # send available PDU(s) back
        if not asn_ngap_acquire():
           gnb._log('ERR', 'unable to acquire the NGAP module')
           return
        for pdu in pdu_tx:
            PDU_NGAP.set_val(pdu)
            if GNBd.TRACE_ASN_NGAP:
                gnb._log('TRACE_ASN_NGAP_DL', PDU_NGAP.to_asn1())
            self._write_sk(sk, PDU_NGAP.to_aper(), ppid=SCTP_PPID_NGAP, stream=sid)
        asn_ngap_release()
    
    # in 5G, gNB are dealing with TA more or less in the same way as in 4G
    _set_gnb_loc    = _set_enb_loc
    _unset_gnb_loc  = _unset_enb_loc
    
    #--------------------------------------------------------------------------#
    # Home-NodeB connection (3G)
    #--------------------------------------------------------------------------#
    
    def _parse_hnbregreq(self, pdu):
        if pdu[0] != 'initiatingMessage' or pdu[1]['procedureCode'] != 1:
            # not initiating / HNBRegisterRequest
            self._log('WNG', 'invalid HNBAP PDU for registering the HNB')
            return
        pIEs, plmn, cellid = pdu[1]['value'][1], None, None
        IEs = pIEs['protocolIEs']
        if 'protocolExtensions' in pIEs:
            Exts = pIEs['protocolExtensions']
        else:
            Exts = []
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
        except Exception:
            return None
    
    def _send_hnbregrej(self, sk, cause):
        IEs = [{'criticality': 'ignore',
                'id': 1, # id-Cause
                'value': (('HNBAP-IEs', 'Cause'), cause)}]
        pdu = ('unsuccessfulOutcome',
               {'criticality': 'ignore',
                'procedureCode': 1,
                'value': (('HNBAP-PDU-Contents', 'HNBRegisterReject'),
                          {'protocolIEs' : IEs})})
        if not asn_hnbap_acquire():
            self._log('ERR', 'unable to acquire the HNBAP module')
        else:
            PDU_HNBAP.set_val(pdu)
            if HNBd.TRACE_ASN_HNBAP:
                self._log('TRACE_ASN_HNBAP_DL', PDU_HNBAP.to_asn1())
            self._write_sk(sk, PDU_HNBAP.to_aper(), ppid=SCTP_PPID_HNBAP)
            asn_hnbap_release()
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
        ppid = ntohl(notif.ppid)
        if ppid != SCTP_PPID_HNBAP:
            self._log('ERR', 'invalid HNBAP PPID, %i' % ppid)
            if self.SERVER_HNB['errclo']:
                sk.close()
            return
        #
        if not asn_hnbap_acquire():
            self._log('ERR', 'unable to acquire the HNBAP module')
            return
        try:
            PDU_HNBAP.from_aper(buf)
        except Exception:
            self._log('WNG', 'invalid HNBAP PDU transfer-syntax: %s'\
                      % hexlify(buf).decode('ascii'))
            asn_hnbap_release()
            # return nothing, no need to bother
            return
        if HNBd.TRACE_ASN_HNBAP:
            self._log('TRACE_ASN_HNBAP_UL', PDU_HNBAP.to_asn1())
        pdu = PDU_HNBAP()
        asn_hnbap_release()
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
                hnb = HNBd(self, sk)
                self.RAN[HNBId] = hnb
        else:
            if self.RAN[HNBId] is None:
                # HNB allowed, but not yet connected
                hnb = HNBd(self, sk)
                self.RAN[HNBId] = hnb
            elif not self.RAN[HNBId].is_connected():
                # HNB already connected and disconnected in the past
                hnb = self.RAN[HNBId]
                hnb.__init__(self, sk)
            else:
                # HNB already connected
                self._log('ERR', 'HNB %r already connected from address %r'\
                          % (HNBId, self.RAN[HNBId].SK.getpeername()))
                if self.SERVER_HNB['errclo']:
                    sk.close()
                return
        #
        # process the initial PDU
        ret = hnb.process_hnbap_pdu(pdu)
        # keep track of the client
        self.SCTPCli[sk] = HNBId
        # add the hnb LAI / RAI to the Server location tables
        if hnb.Config:
            self._set_hnb_loc(hnb)
        #
        # send available PDU(s) back
        if not asn_hnbap_acquire():
           hnb._log('ERR', 'unable to acquire the HNBAP module')
           return
        for retpdu in ret:
            PDU_HNBAP.set_val(retpdu)
            if HNBd.TRACE_ASN_HNBAP:
                hnb._log('TRACE_ASN_HNBAP_DL', PDU_HNBAP.to_asn1())
            self._write_sk(sk, PDU_HNBAP.to_aper(), ppid=SCTP_PPID_HNBAP)
        asn_hnbap_release()
    
    def _set_hnb_loc(self, hnb):
        lai = (hnb.Config['PLMNidentity'], hnb.Config['LAC'])
        rai = lai + (hnb.Config['RAC'], )
        if lai in self.LAI:
            assert( hnb.ID not in self.LAI[lai] )
            self.LAI[lai].add( hnb.ID )
        else:
            self.LAI[lai] = set( (hnb.ID, ) )
        if rai in self.RAI:
            assert( hnb.ID not in self.RAI[rai] )
            self.RAI[rai].add( hnb.ID )
        else:
            self.RAI[rai] = set( (hnb.ID, ) )
    
    def _unset_hnb_loc(self, hnb):
        lai = (hnb.Config['PLMNidentity'], hnb.Config['LAC'])
        rai = lai + (hnb.Config['RAC'], )
        try:
            self.LAI[lai].remove(hnb.ID)
        except Exception:
            self._log('ERR', 'HNB not referenced into the LAI table')
        try:
            self.RAI[rai].remove(hnb.ID)
        except Exception:
            self._log('ERR', 'HNB not referenced into the RAI table')
    
    #--------------------------------------------------------------------------#
    # UE handler
    #--------------------------------------------------------------------------#
    
    def get_ued(self, **kw):
        """return a UEd instance or None, according to the UE identity provided
        
        kw: imsi (digit-str), tmsi (uint32), ptmsi (uint32), mtmsi (uint32) or fgtmsi (uint32)
        
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
                self._log('WNG', 'attaching a UE without dedicated configuration, IMSI %s' % imsi)
                self.UE[imsi] = UEd(self, imsi, config=self.ConfigUE['*'])
                return self.UE[imsi]
            else:
                self._log('INF', 'IMSI not allowed, %s' % imsi)
        elif 'tmsi' in kw:
            tmsi = kw['tmsi']
            if tmsi in self.TMSI:
                return self.UE[self.TMSI[tmsi]]
            else:
                # creating a UEd instance which will request IMSI
                return self.create_dummy_ue(tmsi=tmsi)
        elif 'ptmsi' in kw:
            ptmsi = kw['ptmsi']
            if ptmsi in self.PTMSI:
                return self.UE[self.PTMSI[ptmsi]]
            else:
                # creating a UEd instance which will request IMSI
                return self.create_dummy_ue(ptmsi=ptmsi)
        elif 'mtmsi' in kw:
            mtmsi = kw['mtmsi']
            if mtmsi in self.MTMSI:
                return self.UE[self.MTMSI[mtmsi]]
            else:
                # creating a UEd instance which will request IMSI
                return self.create_dummy_ue(mtmsi=mtmsi)
        elif 'fgtmsi' in kw:
            fgtmsi = kw['fgtmsi']
            if fgtmsi in self.FGTMSI:
                return self.UE[self.FGTMSI[fgtmsi]]
            else:
                # creating a UEd instance which will request SUPI
                return self.create_dummy_ue(fgtmsi=fgtmsi)
        return None
    
    def create_dummy_ue(self, **kw):
        assert( len(kw) == 1 )
        ued = UEd(self, '', **kw)
        self._UEpre[tuple(kw.values())[0]] = ued
        return ued
    
    def is_imsi_allowed(self, imsi):
        if imsi in self.ConfigUE:
            # preconfigured UE
            return True
        elif re.match(self.UE_ATTACH_FILTER, imsi) and '*' in self.ConfigUE:
            # non-preconfigured UE
            return True
        else:
            return False
    
    def is_imei_allowed(self, imei):
        # to be implemented
        return True
    
    def is_imeisv_allowed(self, imeisv):
        # to be implemented
        return True
    
    def clean_ue_proc(self):
        #self._log('DBG', 'clean_ue_proc()')
        # go over all UE and abort() NAS signalling procedures in timeout
        T = time()
        for ue in self.UE.values():
            
            if ue.IuCS is not None:
                
                if ue.IuCS.MM.Proc:
                    for P in ue.IuCS.MM.Proc:
                        if hasattr(P, 'TimerStop') and T > P.TimerStop:
                            P._log('WNG', 'timeout: aborting')
                            P.abort()
                
                if ue.IuCS.CC.Proc:
                    for P in ue.IuCS.CC.Proc.values():
                        if hasattr(P, 'TimerStop') and T > P.TimerStop:
                            P._log('WNG', 'timeout: aborting')
                            P.abort()
                
                if ue.IuCS.SMS.Proc:
                    for P in tuple(ue.IuCS.SMS.Proc.values()):
                        if hasattr(P, 'TimerStop') and T > P.TimerStop:
                            P._log('WNG', 'timeout: aborting')
                            P.abort()
                
                if ue.IuCS.SS.Proc:
                    for P in ue.IuCS.SS.Proc.values():
                        if hasattr(P, 'TimerStop') and T > P.TimerStop:
                            P._log('WNG', 'timeout: aborting')
                            P.abort()
            
            
            if ue.IuPS is not None:
            
                if ue.IuPS.GMM.Proc:
                    for P in ue.IuPS.GMM.Proc:
                        if hasattr(P, 'TimerStop') and T > P.TimerStop:
                            P._log('WNG', 'timeout: aborting')
                            P.abort()
                
                if ue.IuPS.SM.Proc:
                    for P in tuple(ue.IuPS.SM.Proc.values()):
                        if hasattr(P, 'TimerStop') and T > P.TimerStop:
                            P._log('WNG', 'timeout: aborting')
                            P.abort()
            
            if ue.S1 is not None:
            
                if ue.S1.EMM.Proc:
                    for P in ue.S1.EMM.Proc:
                        if hasattr(P, 'TimerStop') and T > P.TimerStop:
                            P._log('WNG', 'timeout: aborting')
                            P.abort()
                
                if ue.S1.ESM.Proc:
                    for P in tuple(ue.S1.ESM.Proc.values()):
                        if hasattr(P, 'TimerStop') and T > P.TimerStop:
                            P._log('WNG', 'timeout: aborting')
                            P.abort()
                
                if ue.S1.SMS.Proc:
                    for P in tuple(ue.S1.SMS.Proc.values()):
                        if hasattr(P, 'TimerStop') and T > P.TimerStop:
                            P._log('WNG', 'timeout: aborting')
                            P.abort()
            
            if ue.NG is not None:
                
                if ue.NG.FGMM.Proc:
                    for P in ue.NG.FGMM.Proc:
                        if hasattr(P, 'TimerStop') and T > P.TimerStop:
                            P._log('WNG', 'timeout: aborting')
                            P.abort()
                
                if ue.NG.FGSM.Proc:
                    for P in tuple(ue.NG.FGSM.Proc.values()):
                        if hasattr(P, 'TimerStop') and T > P.TimerStop:
                            P._log('WNG', 'timeout: aborting')
                            P.abort()
                
                if ue.NG.SMS.Proc:
                    for P in tuple(ue.NG.SMS.Proc.values()):
                        if hasattr(P, 'TimerStop') and T > P.TimerStop:
                            P._log('WNG', 'timeout: aborting')
                            P.abort()
    
    def get_gtp_teid(self):
        if self._GTP_TEID_UL > 4294967294:
            self._GTP_TEID_UL = randint(1, 200000)
        self._GTP_TEID_UL += 1
        return self._GTP_TEID_UL
    
    def send_smsrp(self, msisdn, rp_msg):
        if msisdn not in self.MSISDN:
            # unknown msisdn
            self.SMSd.discard_rp(rp_msg, msisdn)
            return
        imsi = self.MSISDN[msisdn]
        if imsi not in self.UE:
            # UE not attached
            self.SMSd.discard_rp(rp_msg, msisdn)
            return
        ue = self.UE[imsi]
        return ue.smsrp_downlink(rp_msg)

