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
# * File Name : pycrate_corenet/HdlrENB.py
# * Created : 2017-06-28
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from .utils import *


class ENBd(object):
    """eNB handler within a CorenetServer instance
    responsible for S1AP signaling
    """
    
    #--------------------------------------------------------------------------#
    # debug and tracing level
    #--------------------------------------------------------------------------#
    #
    # verbosity level
    DEBUG           = ('ERR', 'WNG', 'INF', 'DBG')
    # to log S1AP PDU
    TRACE_ASN_S1AP  = False
    # to keep track of all S1AP procedures
    TRACK_PROC_S1AP = True
    
    # Radio Access Technology remainder
    RAT = RAT_UTRA
    
    # ID: (PLMN, CellID)
    ID = (None, None)
    
    # SCTP socket
    SK   = None
    Addr = None
    
    # Server reference
    Server = None
    
    # dict to link context-id -> UEd instance
    UE = {}
    
    def _log(self, logtype, msg):
        """ENBd logging facility
        
        DEBUG logtype: 'ERR', 'WNG', 'INF', 'DBG'
        TRACE logtype: 'TRACE_ASN_S1AP_[UL|DL]'
        """
        if logtype[:3] == 'TRA':
            log('[TRA] [ENB: %s.%s] [%s]\n%s%s%s'\
                % (self.ID[0], self.ID[1], logtype[6:], TRACE_COLOR_START, msg, TRACE_COLOR_END))
        elif logtype in self.DEBUG:
            log('[%s] [ENB: %s.%s] %s' % (logtype, self.ID[0], self.ID[1], msg))
    
    def __init__(self, server, sk):
        self.connect(server, sk)
        #
        # init ENB config dict
        self.Config = {}
        #
        # dict of ongoing S1AP procedures (indexed by their procedure code)
        self.ProcS1ap     = {}
        # procedure code of the last procedure emitting a pdu toward the RAN
        self.ProcS1apLast = None
        # list of tracked procedures (requires TRACK_PROC_S1AP = True)
        self._proc        = []
        #
        # counter for UE context id
        self._ctx_id = 0
    
    #--------------------------------------------------------------------------#
    # network socket operations
    #--------------------------------------------------------------------------#
    
    def connect(self, server, sk):
        self.Server = server
        self.SK = sk
        self.Addr = sk.getpeername()
    
    def disconnect(self):
        del self.Server, self.SK, self.Addr
    
    def is_connected(self):
        return self.SK is not None
    
    #--------------------------------------------------------------------------#
    # handling of RAN link procedures
    #--------------------------------------------------------------------------#
    
    def process_s1ap_pdu(self, pdu):
        """process a S1AP PDU sent by the ENB
        and return a list of S1APAP PDU(s) to be sent back to it
        """
        return []

