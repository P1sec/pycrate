# −*− coding: UTF−8 −*−
#/**
# * Software Name : pycrate
# * Version : 0.1.0
# *
# * Copyright © 2017. Benoit Michau. ANSSI.
# *
# * This program is free software: you can redistribute it and/or modify
# * it under the terms of the GNU General Public License version 2 as published
# * by the Free Software Foundation. 
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# * GNU General Public License for more details. 
# *
# * You will find a copy of the terms and conditions of the GNU General Public
# * License version 2 in the "license.txt" file or
# * see http://www.gnu.org/licenses/ or write to the Free Software Foundation,
# * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
# *
# *--------------------------------------------------------
# * File Name : pycrate_corenet/ServerAuC.py
# * Created : 2017-09-01
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

"""
HOWTO:

1) in order to use AuC, the following parameters and files need to be configured:
-> files AuC.db need to be edited with IMSI and authentication parameters from your (U)SIM cards
-> AuC.AUC_DB_PATH can be change if the AuC.db file is put elsewhere
-> AuC.OP needs to be changed according to your Milenage customization

2) To use the AuC (in case your IMSI is '001010000000001'):
>>> MyAuc = AuC()
>>> vec2g = MyAuc.make_2g_vector('001010000000001')
>>> vec3g = MyAuc.make_3g_vector('001010000000001', AMF='\x00\x00')
>>> vec4g = MyAuc.make_4g_vector('001010000000001', SN_ID='\x00\xf1\x10', AMF='\x80\x00')
>>> MyAuc.synchronize('001010000000001', RAND=16*'\0', AMF='\0\0', AUTS=14*'\0')

3) That's all !
"""

# filtering exports
__all__ = ['AuC']

import os
import time as timemod
from binascii import hexlify, unhexlify
from struct   import pack, unpack
from time     import sleep

try:
    from os import urandom as genrand
except ImportError:
    # non-posix platform, use SystemRandom
    from random import SystemRandom
    _rand = SystemRandom()
    genrand = lambda n: uint_to_bytes(_rand.getrandbits(8*n), 8*n)

try:
    from CryptoMobile.Milenage import *
    from pycomp128             import comp128v1, comp128v2, comp128v3
except ImportError as err:
    print('CryptoMobile library is required for Milenage and Comp-128')
    raise(err)

from .utils import *


class AuC:
    """3GPP Authentication Centre
    
    use the AuC.db file with (IMSI, K, SQN[, OP]) records to produce 2G, 3G or
    4G auth vectors, and resynchronize SQN
    """
    
    # verbosity level: list of log types to be displayed
    DEBUG = ('ERR', 'WNG', 'INF', 'DBG')
    
    AUC_DB_PATH = os.path.dirname(os.path.abspath( __file__ )) + os.sep
    #AuC_db_path = 'C:\Python27\Lib\sitepackages\pycrate_corenet\'
    
    # when rewriting the AuC.db, do a back-up of the last version of the file
    DO_BACKUP = True
    
    # MNO OP diversification parameter
    # The AuC supports also a per-subscriber OP, to be set optionally in the AuC.db database
    OP =  b'ffffffffffffffff'
    
    # PLMN restriction for returning 4G vectors
    # provide a list of allowed PLMN, or None for disabling the filter
    #PLMN_FILTER = ['20869']
    PLMN_FILTER = None
    
    
    def __init__(self):
        """start the AuC
        
        open AuC.db file
        parse it into self.db (dict), containing IMSI: (K, SQN [, OP])
            IMSI: string of digits
            K   : 16 bytes buffer
            ALG2: integer (0, 1, 2 or 3, identifies the 2G auth algorithm)
            SQN : unsigned integer
            OP  : subscriber specific OP, distinct from self.OP, optional field
        """
        self._log('DBG', 'AuC starting')
        
        self.db = {}
        try:
            # get 3G authentication database AuC.db
            db_fd = open('%sAuC.db' % self.AUC_DB_PATH, 'r')
            # parse it into a dict object with IMSI as key
            for line in db_fd.readlines():
                if line[0] != '#' and line.count(';') >= 3:
                    fields = line[:-1].split(';')
                    IMSI   = str( fields[0] )
                    K      = unhexlify( fields[1].encode('ascii') )
                    ALG2   = int( fields[2] )
                    SQN    = int( fields[3] )
                    if len(fields) > 4 and len(fields) == 32:
                        OP = unhexlify( fields[4].encode('ascii') )
                    else:
                        OP = None
                    self.db[IMSI] = [ K, ALG2, SQN, OP ]
            self._log('INF', 'AuC.db file opened: %i record(s) found' % len(self.db))
            # close the file
            db_fd.close()
        except Exception as err:
            self._log('ERR', 'unable to read AuC.db, path: %s' % self.AUC_DB_PATH)
            raise(err)
        self._save_required = False
        
        # initiatlize the Milenage algo with the AuC-defined OP
        self.Milenage = Milenage(self.OP)
    
    def _log(self, logtype='DBG', msg=''):
        if logtype in self.DEBUG:
            log('[%s] [AuC] %s' % (logtype, msg))
    
    def save(self):
        """
        optionally save old AuC.db with timestamp suffix (if self.DO_BACKUP is set)
        write the current content of self.db dict into AuC.db, with updated SQN
        values
        """
        if not self._save_required:
            return
        
        T = timemod.strftime( '20%y%m%d_%H%M', timemod.gmtime() )
        
        # get header from original file AuC.db
        header = []
        file_db = open('%sAuC.db' % self.AUC_DB_PATH)
        for line in file_db:
            if line[0] == '#':
                header.append( line )
            else:
                break
        header = ''.join(header) + '\n'
        file_db.close()
        
        if self.DO_BACKUP:
            # save the last current version of AuC.db
            os.rename( '%sAuC.db' % self.AUC_DB_PATH,
                       '%sAuC.%s.db' % (self.AUC_DB_PATH, T) )
            self._log('DBG', 'old AuC.db saved with timestamp')
        
        # save the current self.db into a new AuC.db file
        file_db = open('%s/AuC.db' % self.AUC_DB_PATH, 'w')
        file_db.write( header )
        indexes = list(self.db.keys())
        indexes.sort()
        for IMSI in indexes:
            K, ALG2, SQN, OP = self.db[IMSI]
            if OP is not None:
                # OP additional parameter
                file_db.write('%s;%s;%i;%i;%s;\n'\
                    % (IMSI, hexlify(K).decode('ascii'), ALG2, SQN, hexlify(OP).decode('ascii')))
            else:
                file_db.write('%s;%s;%i;%i;\n'\
                    % (IMSI, hexlify(K).decode('ascii'), ALG2, SQN))
        file_db.close()
        self._log('INF', 'current db saved to AuC.db file')
    
    stop = save
    
    def make_2g_vector(self, IMSI, RAND=None):
        """
        return a 2G authentication vector "triplet":
        RAND [16 bytes], RES [4 bytes], Kc [8 bytes]
        or None if the IMSI is not defined in the db or ALG2 is invalid
        
        RAND can be passed as argument
        """
        # lookup db for authentication Key and algorithm id for IMSI
        try:
            K, ALG2, SQN, OP = self.db[IMSI]
        except KeyError:
            self._log('WNG', '[make_2g_vector] IMSI %s not present in AuC.db' % IMSI)
            return None
        #
        if not RAND:
            RAND = genrand(16)
        #
        if ALG2 == 0:
            if OP is not None:
                XRES, CK, IK, AK = self.Milenage.f2345(RAND, K, OP)
            else:
                XRES, CK, IK, AK = self.Milenage.f2345(RAND, K)
            RES, Ck = conv_C2(XRES), conv_C3(Ck, Ik)
        else:
            if ALG2 == 1:
                RES, Ck = comp128v1(K, RAND)
            elif ALG2 == 2:
                RES, Ck = comp128v2(K, RAND)
            elif ALG2 == 3:
                RES, Ck = comp128v3(K, RAND)
            else:
                return None
        #
        # return auth vector
        self._log('DBG', '[make_2g_vector] IMSI %s: RAND %s, RES %s, Kc %s'\
                  % (IMSI, hexlify(RAND).decode('ascii'), hexlify(RES).decode('ascii'), 
                     hexlify(Kc).decode('ascii')))
        return RAND, RES, Kc
    
    def make_3g_vector(self, IMSI, AMF=b'\0\0', RAND=None):
        '''
        return a 3G authentication vector "quintuplet":
        RAND [16 bytes], XRES [8 bytes], AUTN [16 bytes], CK [16 bytes], IK [16 bytes]
        or None if the IMSI is not defined in the db or does not support Milenage
        
        RAND can be passed as argument
        '''
        # lookup db for authentication Key and counter for IMSI
        try:
            K_ALG2_SQN_OP = self.db[IMSI]
        except:
            self._log('WNG', '[make_3g_vector] IMSI %s not present in AuC.db' % IMSI)
            return None
        #
        K, ALG2, SQN, OP = K_ALG2_SQN_OP
        #
        if SQN == -1:
            # Milenage not supported
            self._log('WNG', '[make_3g_vector] IMSI %s does not support Milenage' % IMSI)
            return None
        #
        # increment SQN counter in the db
        K_ALG2_SQN_OP[2] += 1
        self._save_required = True
        
        # pack SQN from integer to a 48-bit buffer
        SQNb = b'\0\0' + pack('>I', SQN)
        
        # generate challenge if necessary
        if RAND is None:
            RAND = genrand(16)
        
        # compute Milenage functions
        if OP is not None:
            XRES, CK, IK, AK = self.Milenage.f2345( K, RAND, OP )
            MAC_A            = self.Milenage.f1( K, RAND, SQNb, AMF, OP )
            AUTN             = xor_buf( SQNb, AK ) + AMF + MAC_A
        else:
            XRES, CK, IK, AK = self.Milenage.f2345( K, RAND )
            MAC_A            = self.Milenage.f1( K, RAND, SQNb, AMF )
            AUTN             = xor_buf( SQNb, AK ) + AMF + MAC_A
        
        # return auth vector
        self._log('DBG', '[make_3g_vector] IMSI %s, SQN %i: RAND %s, XRES %s, AUTN %s, CK %s, IK %s'\
                  % (IMSI, SQN, hexlify(RAND).decode('ascii'), hexlify(XRES).decode('ascii'),
                     hexlify(AUTN).decode('ascii'), hexlify(CK).decode('ascii'), 
                     hexlify(IK).decode('ascii')))
        return RAND, XRES, AUTN, CK, IK
    
    def make_4g_vector(self, IMSI, SN_ID, AMF=b'\x80\x00', RAND=None):
        """
        return a 4G authentication vector "quadruplet":
        RAND [16 bytes], XRES [8 bytes], AUTN [16 bytes], KASME [32 bytes]
        or None if the IMSI is not defined in the db or does not support Milenage
        or SN_ID is invalid or not allowed
        
        SN_ID is the serving network identity, bcd-encoded buffer
        RAND can be passed as argument
        """
        if not isinstance(SN_ID, bytes_types) or len(SN_ID) != 3:
            self._log('WNG', '[make_4g_vector] SN_ID invalid, %s' % hexlify(SN_ID).decode('ascii'))
            return None
        elif self.PLMN_FILTER is not None and SN_ID not in self.PLMN_FILTER:
            self._log('WNG', '[make_4g_vector] SN_ID not allowed, %s' % hexlify(SN_ID).decode('ascii'))
            return None
        #
        # lookup db for authentication Key and counter for IMSI
        try:
            K_ALG2_SQN_OP = self.db[IMSI]
        except:
            self._log('WNG', '[make_4g_vector] IMSI %s not present in AuC.db' % IMSI)
            return None
        #
        K, ALG2, SQN, OP = K_ALG2_SQN_OP
        #
        if SQN == -1:
            # Milenage not supported
            self._log('WNG', '[make_4g_vector] IMSI %s does not support Milenage' % IMSI)
            return None
        #
        # increment SQN counter in the db
        K_ALG2_SQN_OP[2] += 1
        self._save_required = True
        
        # pack SQN from integer to a 48-bit buffer
        SQNb = b'\0\0' + pack('>I', SQN)
        #
        # generate challenge
        if RAND is None:
            RAND = genrand(16)
        
        # compute Milenage functions
        if OP is not None:
            XRES, CK, IK, AK = self.Milenage.f2345( K, RAND, OP )
            MAC_A            = self.Milenage.f1( K, RAND, SQNb, AMF, OP )
            SQN_X_AK         = xor_buf( SQNb, AK )
            AUTN             = SQN_X_AK + AMF + MAC_A
        else:
            XRES, CK, IK, AK = self.Milenage.f2345( K, RAND )
            MAC_A            = self.Milenage.f1( K, RAND, SQNb, AMF )
            SQN_X_AK         = xor_buf( SQNb, AK )
            AUTN             = SQN_X_AK + AMF + MAC_A
        
        # convert to LTE master key
        KASME = conv_A2(CK, IK, SN_ID, SQN_X_AK)
        
        # return auth vector
        self._log('DBG', '[make_4g_vector] IMSI %s, SQN %i, SN_ID %s: RAND %s, XRES %s, AUTN %s, KASME %s'\
                  % (IMSI, SQN, hexlify(SN_ID).decode('ascii'), hexlify(RAND).decode('ascii'), 
                     hexlify(XRES).decode('ascii'), hexlify(AUTN).decode('ascii'), 
                     hexlify(KASME).decode('ascii')))
        return RAND, XRES, AUTN, KASME
    
    def synch_sqn(self, IMSI, RAND, AUTS):
        """
        synchronize the local counter SQN with AUTS provided by the USIM
        in response to a given 3G or 4G authentication challenge (RAND, AMF)
        
        return 0 on successful synch, 1 on unsuccessful synch due to invalid AUTS
        or None if the IMSI is not defined in the db
        """
        # lookup db for authentication Key and counter for IMSI
        try:
            K_ALG2_SQN_OP = self.db[IMSI]
        except:
            self._log('WNG', '[synch_sqn] IMSI %s not present in AuC.db' % IMSI)
            return None
        #
        K, ALG2, SQN, OP = K_ALG2_SQN_OP
        #
        if K_ALG2_SQN_OP[2] == -1:
            # Milenage not supported
            self._log('WNG', '[make_3g_vector] IMSI %s does not support Milenage' % IMSI)
            return None
        #
        # 33.102, section 6.3.3, for resynch, AMF is always null (0x0000)
        AMF = b'\0\0'
        #
        # compute Milenage functions and unmask SQN
        if OP is not None:
            AK      = self.Milenage.f5star( K, RAND, OP )
            SQN_MS  = xor_buf( AUTS[0:6], AK )
            MAC_S   = self.Milenage.f1star( K, RAND, SQN_MS, AMF, OP )
            SQN_MSi = unpack('>Q', b'\0\0' + SQN_MS)[0]
        else:
            AK      = self.Milenage.f5star( K, RAND )
            SQN_MS  = xor_buf( AUTS[0:6], AK )
            MAC_S   = self.Milenage.f1star( K, RAND, SQN_MS, AMF )
            SQN_MSi = unpack('>Q', b'\0\0' + SQN_MS)[0]
        
        self._log('DBG', '[synch_sqn] USIM resynchronization, SQN_MS %i, MAC_S %s'\
                  % (SQN_MSi, hexlify(MAC_S).decode('ascii')))
        
        # authenticate the USIM
        if MAC_S != AUTS[6:14]:
            self._log('WNG', '[synch_sqn] IMSI %s, USIM authentication failure' % IMSI)
            return 1
        
        # resynchronize local SQN value
        K_ALG2_SQN_OP[2] = SQN_MSi + 1
        self._save_required = True
        self._log('DBG', '[synch_sqn] IMSI %s, SQN resynchronized to %i' % (IMSI, K_ALG2_SQN_OP[2]))
        return 0

