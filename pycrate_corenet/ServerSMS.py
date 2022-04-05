# −*− coding: UTF−8 −*−
#/**
# * Software Name : pycrate 
# * Version : 0.4
# *
# * Copyright 2013. Benoit Michau. ANSSI.
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
# * File Name : pycrate_corenet/ServerSMS.py
# * Created : 2013-11-04
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

__all__ = ['SMSd']

from time   import localtime
from .utils import *
if python_version < 3:
    from Queue import Queue, Empty, Full
else:
    from queue import Queue, Empty, Full


class SMSd(object):
    '''
    Very basic SMS relay
    Receive, acknowledge and forward SMS-RP messages
    '''
    #
    # verbosity level: list of log types to display when calling 
    # self._log(logtype, msg)
    DEBUG = ('ERR', 'WNG', 'INF', 'DBG')
    #
    TRACK_PDU = True
    #
    # time resolution for consuming the queue for TP msg
    QUEUE_TO  = 0.1
    #
    # SMS relay phone number
    RP_OA = {'Type': 1, 'NumberingPlan': 1, 'Num': '1234'}
    #
    # TP settings for sending handcrafted SMS DELIVER to UEs 
    TP_OA  = {'Type': 1, 'NumberingPlan': 1, 'Num': '12341234'}
    TP_PID = {'Format': 0, 'Telematic': {'Telematic': 0, 'Protocol': 0}}
    TP_DCS = {'Group': 0, 'Charset': 0, 'Class': 0}
    #
    # timezone for TP_SCTS information (float)
    TIMEZONE = 0.0
    #
    # CorenetServer reference, for checking UE MSISDN and sending MT-SMS
    Server = None
    
    def __init__(self):
        self._pdu = []
        # dict with dicts of ongoing RP transactions indexed by RP ref and 
        #                    ongoing TP transactions indexed by TP msg ref
        # indexed by UE msisdn
        self.Proc = {}
        # dict with lists of RP-DATA and TP procedures in error, indexed by UE msisdn 
        self.Err  = {}
        #
        # set 2 queues to process / forward or inject TP messages within a background thread
        self._forward_q  = Queue()
        self._inject_q   = Queue()
        self._forwarding = True
        self._forward_t  = threadit(self.forward)
        self._log('INF', 'SMS relay started')
    
    def _log(self, logtype='DBG', msg=''):
        # logtype: 'ERR', 'WNG', 'INF', 'DBG'
        if logtype in self.DEBUG:
            log('[%s] [SMSd] %s' % (logtype, msg))
    
    def stop(self):
        if self._forwarding:
            self._forwarding = False
            self._forward_t.join()
    
    def forward(self):
        # consume the queue
        while self._forwarding:
            try:
                tp_msg, num = self._forward_q.get_nowait()
            except Empty:
                try:
                    tp_msg, num = self._inject_q.get_nowait()
                except Empty:
                    sleep(self.QUEUE_TO)
                else:
                    self.send_tp(tp_msg, num)
            else:
                self.process_tp(tp_msg, num)
    
    def init_ue(self, num):
        self.Proc[num] = {
            'RP': {}, # dict of ongoing RP procedures at the RP layer
            'TP': {}  # dict of ongoing TP procedures at the TP layer
            }
        self.Err[num] = {
            'RP': [], # list of RP procedures in error
            'TP': []  # list of TP procedures in error
            }
    
    def process_rp(self, rp_msg, num):
        """process an RP message `rp_msg' sent by a UE with a given MSISDN `num',
        
        returns an RP ACK or ERROR if rp_msg is DATA or SMMA
                None if rp_msg is ACK or ERROR
        """
        if not isinstance(rp_msg, NAS.SMS_RP):
            self._log('WNG', 'process_rp: invalid rp_msg')
            return None
        #
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'UL', rp_msg) )
        #
        if num not in self.Proc:
            self.init_ue(num)
        #
        if rp_msg._name == 'RP_DATA_MO':
            # this will return an RP_ACK or RP_ERR
            ret = self._process_rp_data(rp_msg, num)
        elif rp_msg._name == 'RP_SMMA':
            # this will return an RP_ACK or RP_ERR
            ret = self._process_rp_smma(rp_msg, num)
        elif rp_msg._name in ('RP_ACK_MO', 'RP_ERROR_MO'):
            # check the ref together with num
            ret = self._process_rp_ack_err(rp_msg, num)
        else:
            self._log('WNG', 'process_rp: invalid message %r' % rp_msg)
            ret = None
        #
        if ret and self.TRACK_PDU:
            self._pdu.append( (time(), 'DL', ret) )
        return ret
    
    def _process_rp_data(self, rp_msg, num):
        ref = rp_msg[2].get_val()
        rp_procs = self.Proc[num]['RP']
        rp_procs[ref] = (rp_msg, None)
        #
        # check RP orig / dest address
        if rp_msg[3][0].get_val() > 0:
            rp_orig = rp_msg[3][1]
            self._log('WNG', 'process_rp_data: non-empty originator address, %r' % rp_orig)
            # invalid mandatory information
            del rp_procs[ref] 
            return NAS.RP_ERROR_MT(val={'Ref': ind[1], 'RPCause': {'Value': 96}})
        #
        if rp_msg[4][0].get_val() > 0:
            rp_dest = rp_msg[4][1]
            if rp_dest['Num'].decode() != self.RP_OA['Num']:
                self._log('INF', 'process_rp_data: destination address, %r' % rp_dest)
        else:
            self._log('WNG', 'process_rp_data: empty destination address')
            # invalid mandatory information
            del rp_procs[ref]
            return NAS.RP_ERROR_MT(val={'Ref': ind[1], 'RPCause': {'Value': 96}})
        #
        if not isinstance(rp_msg[5][1], NAS.SMS_TP):
            self._log('WNG', 'process_rp_data: invalid TP data, %r' % tp_msg[5])
            # invalid mandatory information
            del rp_procs[ref]
            return NAS.RP_ERROR_MT(val={'Ref': ind[1], 'RPCause': {'Value': 96}})
        #
        # process TP in the background thread
        self._insert_tp(rp_msg[5][1], num)
        # acknowledge RP
        rp_ack = NAS.RP_ACK_MT(val={'Ref': ref})
        del rp_procs[ref]
        return rp_ack
    
    def _process_rp_smma(self, rp_msg, num):
        ref = rp_msg[2].get_val()
        self._log('INF', 'process_rp_smma: procedure ref (%s, %i)' % (num, ref))
        return NAS.RP_ACK_MT(val={'Ref': ref})
    
    def _process_rp_ack_err(self, rp_msg, num):
        rp_msg_name = rp_msg._name[:-3].replace('_', '-')
        ref = rp_msg[2].get_val()
        rp_procs = self.Proc[num]['RP']
        if ref in rp_procs:
            rp_req, tp_ref = rp_procs[ref]
            rp_ud  = rp_msg['RPUserData']
            if not rp_ud.get_trans() and isinstance(rp_ud[2], NAS.SMS_TP):
                # SMS_DELIVER_REPORT_RP_ACK/ERROR provided
                if rp_msg._name == 'RP_ACK_MO':
                    # TP status 0: Short message transaction completed - Short message received by the SME
                    stat = 0
                else:
                    # TP status 64: Permanent error, SC is not making any more transfer attempts - Remote procedure error
                    stat = 64
                self._report_status(rp_req, tp_ref, stat)
                # TODO: check if it requires an RP-ACK back
            # delete the RP procedure
            del rp_procs[ref]
            if rp_msg_name == 'RP-ACK':
                self._log('DBG', 'process_rp_ack_err: procedure ref (%s, %i) completed' % (num, ref))
            else:
                self.Err[num]['RP'].append(rp_req)
                self._log('INF', 'process_rp_ack_err: procedure ref (%s, %i) in error with cause %r'\
                          % (num, ref, rp_msg[3][1]))
        else:
            self._log('INF', 'process_rp_ack_err: procedure ref (%s, %i) unknown' % (num, ref))
        return None
    
    def _report_status(self, rp_req, tp_ref, stat=64):
        # when a downlink RP-DATA fails within CorenetServer (-> discard_rp())
        # or receiving an RP-ACK/ERROR-MO with TP data (SMS-DELIVER-REPORT-RP-ACK/ERROR)
        # we need to start an SMS-STATUS-REPORT toward to original sender
        # 1) reassociate to the SMS SUBMIT of the initial sender
        try:
            tp_oa = rp_req[5][1]['TP_OA']['Num'].decode()
        except Exception:
            self._log('WNG', 'report_status: unable to retrieve the TP originating address')
        else:
            if tp_oa in self.Proc:
                tp_procs = self.Proc[tp_oa]['TP']
                if tp_ref in tp_procs:
                    tp_req, atime = self.Proc[tp_oa]['TP'][tp_ref]
                    # 2) send a status report to the initial sender and delete the TP transaction
                    del self.Proc[tp_oa]['TP'][tp_ref]
                    tp_stat = self._create_tp_stat_rep(tp_req, tp_oa, atime, stat)
                    self._inject_tp(tp_stat, tp_oa)
                    self._log('DBG', 'report_status: delete TP procedure (%s, %i)' % (tp_oa, tp_ref))
                    return
            # no status report was requested, hence we just pass our way
            self._log('DBG', 'report_status: no SMS SUBMIT requiring status report for %s' % tp_oa)
    
    def _insert_tp(self, tp_msg, num):
        """put the tp_msg within the forwarding queue,
        and let the forwarding thread take care of it
        """
        try:
            self._forward_q.put_nowait( (tp_msg, num) )
        except Full as err:
            self._log('ERR', 'insert_tp: TP forwarding queue is full (%i), deleting it, %s'\
                      % (self._forward_q.qsize(), err))
            self._forward_q = Queue()
    
    def process_tp(self, tp_msg, num):
        """process a TP message `tp_msg' sent by a UE with a given MSISDN `num'
        """
        if tp_msg._name == 'SMS_SUBMIT':
            # should forward TP user data in an SMS DELIVER to the TP dest
            self._process_tp_submit(tp_msg, num)
        elif tp_msg._name == 'SMS_COMMAND':
            # correspond to an MS invoking an operation within the SMS-Center
            self._process_tp_cmd(tp_msg, num)
        else:
            # SMS_DELIVER_REPORT_RP_ACK and SMS_DELIVER_REPORT_RP_ERROR
            # are processed within _process_rp_ack_err()
            self._log('WNG', 'process_tp: invalid message %r' % tp_msg)
            return None
    
    def _process_tp_submit(self, tp_msg, num):
        atime = localtime()
        if tp_msg[0].get_val():
            # the sender UE requests a status report as a result of the SMS DELIVER process
            tp_ref = tp_msg[6].get_val()
        else:
            tp_ref = None
        #
        # check TP dest addr
        num_dest = tp_msg[7]['Num'].decode()
        if num_dest in self.Server.MSISDN:
            imsi = self.Server.MSISDN[num_dest]
        else:
            # unknown msisdn
            # status 65: incompatible dest
            self._log('INF', 'process_tp_submit: destination unknown, %s' % num_dest)
            if tp_ref:
                tp_stat = self._create_tp_stat_rep(tp_msg, num, atime, stat=65)
                self.send_tp(tp_stat, num)
            return
        #
        if imsi in self.Server.UE:
            ued = self.Server.UE[imsi]
        else:
            # UE never attached
            # status 34: no response from SME
            self._log('INF', 'process_tp_submit: destination offline, %s' % num_dest)
            if tp_ref:
                tp_stat = self._create_tp_stat_rep(tp_msg, num, atime, stat=34)
                self.send_tp(tp_stat, num)
            return
        #
        # build tp_deliver
        if tp_ref is not None:
            # keep track of the SMS SUBMIT for further status report
            self.Proc[num]['TP'][tp_ref] = (tp_msg, atime)
        tp_del = self._create_tp_deliver(tp_msg, num, atime)
        self.send_tp(tp_del, num_dest, report_ref=tp_ref)
    
    def _process_tp_cmd(self, tp_msg, num):
        self._log('INF', 'process_tp_cmd: CDL %i, CD 0x%s'\
                  % (tp_msg['TP_CDL'].get_val(),
                     hexlify(tp_msg['TP_CD'].get_val()).decode('ascii')))
        atime = localtime()
        if tp_msg[0].get_val():
            # the sender UE requests a status report of the result of the SMS COMMAND process
            tp_stat = self._create_tp_stat_rep(tp_msg, num, atime, stat=0)
            self.send_tp(tp_stat, num_dest)
    
    def _create_tp_stat_rep(self, tp_msg, num, atime, stat=64):
        tp_srq  = 1 if isinstance(tp_msg, NAS.SMS_COMMAND) else 0
        tp_mr   = tp_msg[6].get_val()
        tp_ra   = {'Type': 1, 'NumberingPlan': 1, 'Num': num}
        tp_scts = (atime, self.TIMEZONE)
        if 0 <= stat <= 255:
            tp_stat = stat
        else:
            tp_stat = 64
        #
        tp_stat = NAS.SMS_STATUS_REPORT(val={
            'TP_SRQ' : tp_srq,
            'TP_MR'  : tp_mr,
            'TP_RA'  : tp_ra,
            'TP_SCTS': tp_scts,
            'TP_ST'  : stat})
        tp_stat['TP_PI'].set_trans(True)
        self._set_tp_scts(tp_stat['TP_DT'])
        return tp_stat
    
    def _create_tp_deliver(self, tp_msg, num, atime):
        tp_sri  = tp_msg[0].get_val()
        tp_udhi = tp_msg[1].get_val()
        tp_oa   = {'Type': 1, 'NumberingPlan': 1, 'Num': num}
        tp_pid  = tp_msg[8].get_val()
        tp_dcs  = tp_msg[9].get_val()
        tp_msg_ud = tp_msg['TP_UD']
        if tp_udhi:
            tp_udh = tp_msg_ud[1][1].get_val()
        else:
            tp_udh = None
        tp_ud   = tp_msg_ud[2].get_val()
        #
        tp_del = NAS.SMS_DELIVER(val={
            'TP_SRI' : tp_sri,
            'TP_UDHI': tp_udhi,
            'TP_OA'  : tp_oa,
            'TP_PID' : tp_pid,
            'TP_DCS' : tp_dcs,
            'TP_UD'  : {'UDH': {'UDH': tp_udh}, 'UD': tp_ud}
            })
        self._set_tp_scts(tp_del['TP_SCTS'])
        return tp_del
    
    def _set_tp_scts(self, tp_scts):
        if tp_scts.get_len() == 7:
            T = localtime()
            tp_scts.encode(localtime(), tz=self.TIMEZONE)
        else:
            self._log('WNG', 'set_tp_scts: custom timestamping unhandled')
    
    def _inject_tp(self, tp_msg, num):
        """put the tp_msg within the injection queue,
        and let the forwarding thread take care of it
        """
        try:
            self._inject_q.put_nowait( (tp_msg, num) )
        except Full as err:
            self._log('ERR', 'inject_tp: TP injection queue is full (%i), deleting it, %s'\
                      % (self._inject_q.qsize(), err))
            self._inject_q = Queue()
    
    def _get_new_rp_ref(self, num):
        if num not in self.Proc:
            self.init_ue(num)
            return 0
        else:
            for i in range(0, 257):
                if i not in self.Proc[num]['RP']:
                    break
            if i == 256:
                # no RP ref available...
                self._log('ERR', 'get_new_rp_ref: no RP ref available, clearing all procedure for %s'\
                          % num)
                self.Proc[num]['RP'].clear()
                self.Proc[num]['TP'].clear()
                return 0
            else:
                return i
    
    def send_tp(self, tp_msg, num, tp_ref=None):
        """send the SMS TP message `tp_msg' to UE msisdn `num'
        associate the TP transaction ref `tp_ref' to the RP transaction
        """
        # wrap the TP msg into an RP DATA msg
        ref = self._get_new_rp_ref(num)
        rp_msg = NAS.RP_DATA_MT(val={'Ref': ref,
                                     'RPOriginatorAddress': self.RP_OA})
        rp_msg.set_tpdu(tp_msg)
        self.Proc[num]['RP'][ref] = (rp_msg, tp_ref)
        self._log('DBG', 'sending TP msg with RP ref %i' % ref)
        self.send_rp(rp_msg, num)
    
    def send_rp(self, rp_msg, num):
        if self.TRACK_PDU:
            self._pdu.append( (time(), 'DL', rp_msg) )
        self.Server.send_smsrp(num, rp_msg)
    
    def discard_rp(self, rp_msg, num):
        """discard an RP message `rp_msg' sent to UE with msisdn `num'
        """
        if num not in self.Proc:
            return
        rp_procs = self.Proc[num]['RP']
        ref = rp_msg[2].get_val()
        if ref not in rp_procs:
            return
        rp_req, tp_ref = rp_procs[ref]
        if tp_ref is not None:
            # downlink RP-DATA failed within corenet, status report required
            # TP status 97 : Temporary error, SC is not making any more transfer attempts - SME busy
            self._report_status(rp_req, tp_ref, 97)
        # delete the RP transaction
        del rp_procs[ref]
        self._log('INF', 'discard_rp: delete RP procedure (%s, %i)' % (num, ref))
    
    #--------------------------------------------------------------------------#
    # custom methods to send TP messages from the SMSd to UEs
    #--------------------------------------------------------------------------#
    
    def send_text(self, text, num):
        """sends a given text (ascii string, that will be converted to SMS 7bit)
        to a given phone number
        """
        tp_dcs = self.TP_DCS
        self.TP_DCS = {'Group': 0, 'Charset': 0, 'Class': 0} # GSM 7bit
        self.send_tpud(text, num=num)
        self.TP_DCS = tp_dcs
    
    def send_tpud(self, ud, num):
        """sends a given user-data (directly the data buffer, or a tuple with 
        options and the data buffer) to a given phone number
        
        each option must be a 2-tuple (Tag, Value) were Tag is an uint8 and Value
        is a buffer
        """
        # TODO: implement SMS UD fragmentation into several tp_msg
        try:
            tp_msg = NAS.SMS_DELIVER(val={'TP_MMS': 1, # no more messages
                                          'TP_OA' : self.TP_OA,
                                          'TP_PID': self.TP_PID,
                                          'TP_DCS': self.TP_DCS})
            self._set_tp_scts(tp_msg['TP_SCTS'])
            if isinstance(ud, (list, tuple)):
                if len(ud) > 1:
                    # UD header IEs
                    tp_msg['TP_UDHI'].set_val(1)
                    tp_msg['TP_UD']['UDH']['UDH'].set_val(
                        [{'T': udh[0], 'V': udh[1]} for udh in ud[:-1]])
                data = ud[-1]
            else:
                data = ud
            tp_msg['TP_UD']['UD'].set_val(data)
        except Exception:
            self._log('WNG', 'invalid TP UD')
        else:
            self._inject_tp(tp_msg, num)
