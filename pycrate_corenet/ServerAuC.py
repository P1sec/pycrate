# −*− coding: UTF−8 −*−
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
>>> vec3g = MyAuc.make_3g_vector('001010000000001', AMF=b'\x00\x00')
>>> vec4g = MyAuc.make_4g_vector('001010000000001', SN_ID=b'\x00\xf1\x10', AMF=b'\x80\x00')
>>> vec5g = MyAuc.make_5g_vector('001010000000001', SNName=b'5G:mnc001.mcc001.3gppnetwork.org', AMF=b'\x80\x00')
>>> MyAuc.synch_sqn('001010000000001', RAND=16*b'\x00', AMF=b'\x00\x00', AUTS=14*b'\x00')

3) That's all !
"""

# filtering exports
__all__ = ['AuC']


import os
import time as timemod
from binascii import hexlify, unhexlify
from struct   import pack, unpack
from time     import sleep

# random generator
try:
    from os import urandom as genrand
except ImportError:
    # non-posix platform, use SystemRandom
    from random import SystemRandom
    _rand = SystemRandom()
    genrand = lambda n: uint_to_bytes(_rand.getrandbits(8*n), 8*n)


# CryptoMobile imports
try:
    from CryptoMobile.Milenage  import Milenage
    from CryptoMobile.TUAK      import TUAK
    from pycomp128              import comp128v1, comp128v2, comp128v3
    from CryptoMobile.utils     import xor_buf, CMException
    from CryptoMobile.conv      import (
        conv_102_C2, conv_102_C3, conv_401_A2, conv_501_A2, conv_501_A4
        )
except ImportError as err:
    print('CryptoMobile library is required for Milenage, TUAK and Comp-128')
    raise(err)

# CryptoMobile with cryptography backend import
try:
    from CryptoMobile.ECIES import ECIES_HN
except ImportError as err:
    print('CryptoMobile library with cryptography backend is required for ECIES / SIDF')
    raise(err)


# local utilities
from .utils import *


class AuC:
    """3GPP Authentication Centre (AuC), ARPF and SIDF
    
    Use the AuC.db file with (IMSI, K, SQN[, OP]) records to then produce 2G, 3G, 
    4G or 5G authentication vectors, and resynchronize SQN. It supports all standard 
    authentication algorithms: comp123v1, v2, v3, Milenage and TUAK.
    Set SIDF home-network private keys for profile A and / or B and use it to decrypt
    concealed subscriber 5G identities.
    """
    
    # verbosity level: list of log types to be displayed
    DEBUG = ('ERR', 'WNG', 'INF', 'DBG')
    
    # path to the local AuC.db file, should be overwritten
    AUC_DB_PATH = os.path.dirname(os.path.abspath( __file__ )) + os.sep
    
    # when rewriting the AuC.db, do a back-up of the last version of the file
    DO_BACKUP = True
    
    # MNO OP (Milenage) and TOP (TUAK) diversification parameter
    # The AuC supports also a per-subscriber OP / TOP, to be set optionally in the AuC.db database
    OP  = b'ffffffffffffffff'
    TOP = b'ffffffffffffffffffffffffffffffff'
    
    # SQN incrementation when a resynch is required by a USIM card
    SQN_SYNCH_STEP = 2
    
    # PLMN restriction for returning 4G and 5G vectors
    # provide a list of allowed PLMN, or None for disabling the filter
    #PLMN_FILTER = ['20869']
    PLMN_FILTER = None
    
    # SIDF ECIES private keys dict, for decrypting SUCI
    # index: Home Network Public Key Identifier (0..255), according to TS 31.102, section 4.4.11.8
    # value: 2-tuple with Protection Scheme Identifier (profile 'A' or 'B') and 
    #        corresponding Home Network Private Key value
    # 
    # ECIES public / private keypairs must be generated according to the CryptoMobile.ECIES API
    #
    SIDF_ECIES_K = {
        #
        # X25519 example keypair (WARNING: use one you generated yourself):
        # pubkey: d6797fcf69c55e889e5bdf9fc4d300eff2aa5b539bb9e97efe14ca244727b029
        #0 : ('A', unhexlify('38859b29cbbdee43fda218968f8b96bb9a7326ec05b43343939220fa2ac1ec56')),
        #
        # secp256r1 example keypair (WARNING: use one you generated yourself):
        # pubkey: 02519c4707c3535eb5a86a66d056696a45537d4d76e8997375dcd7d30b1f37c6c5
        #1 : ('B', unhexlify('308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02'\
        #                    '01010420d633fa02b1808226c0a27ddf093e332751f10cb002e8236d3723bb44'\
        #                    '33a55d41a14403420004519c4707c3535eb5a86a66d056696a45537d4d76e899'\
        #                    '7375dcd7d30b1f37c6c50fb946aec017a332ff00e3993f35b54992004894f7d2'\
        #                    'fc1ee0df47fde0c91cf8')
        }
    
    def __init__(self):
        """start the AuC
        
        open AuC.db file
        parse it into self.db (dict), containing IMSI: (K, SQN [, OP])
            IMSI: string of digits
            K   : 16 bytes buffer
            ALG : integer (0, 1, 2, 3 or 4, identifies the auth algorithm)
            SQN : unsigned integer
            OP  : subscriber specific OP, distinct from self.OP, optional field
        """
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
                    ALG    = int( fields[2] )
                    SQN    = int( fields[3] )
                    if len(fields) > 4 and len(fields[4]) == 32:
                        OP = unhexlify( fields[4].encode('ascii') )
                    else:
                        OP = None
                    self.db[IMSI] = [ K, ALG, SQN, OP ]
            self._log('INF', 'AuC.db file opened: %i record(s) found' % len(self.db))
            # close the file
            db_fd.close()
        except Exception as err:
            self._log('ERR', 'unable to read AuC.db, path: %s' % self.AUC_DB_PATH)
            raise(err)
        self._save_required = False
        #
        # initialize the Milenage algo with the AuC-defined OP
        self.Milenage = Milenage(self.OP)
        # initialize the TUAK algo with the AuC-defined TOP
        self.TUAK     = TUAK(self.TOP)
        # initialize the SIDF function
        self._init_sidf()
        #
        self._log('DBG', 'AuC / ARPF / SIDF started')
    
    def _init_sidf(self):
        self._SIDF_ECIES = {}
        for ind, (prof, key) in self.SIDF_ECIES_K.items():
            self._SIDF_ECIES[ind] = ECIES_HN(hn_priv_key=key, profile=prof)
    
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
            K, ALG, SQN, OP = self.db[IMSI]
            if OP is not None:
                # OP additional parameter
                file_db.write('%s;%s;%i;%i;%s;\n'\
                    % (IMSI, hexlify(K).decode('ascii'), ALG, SQN, hexlify(OP).decode('ascii')))
            else:
                file_db.write('%s;%s;%i;%i;\n'\
                    % (IMSI, hexlify(K).decode('ascii'), ALG, SQN))
        file_db.close()
        self._log('INF', 'current db saved to AuC.db file')
    
    stop = save
    
    def make_2g_vector(self, IMSI, RAND=None):
        """
        return a 2G authentication vector "triplet":
        RAND [16 bytes], RES [4 bytes], Kc [8 bytes]
        or None if the IMSI is not defined in the db or ALG is invalid
        
        RAND can be passed as argument
        """
        # lookup db for authentication Key and algorithm id for IMSI
        try:
            K_ALG_SQN_OP = self.db[IMSI]
        except KeyError:
            self._log('WNG', '[make_2g_vector] IMSI %s not present in AuC.db' % IMSI)
            return None
        if len(K_ALG_SQN_OP) == 4:
            K, ALG, SQN, OP = K_ALG_SQN_OP
        else:
            K, ALG, SQN = K_ALG_SQN_OP
            OP = None
        #
        if not RAND:
            RAND = genrand(16)
        #
        if ALG == 0:
            # Milenage, adapted to 2G
            if OP is not None:
                XRES, CK, IK, AK = self.Milenage.f2345(RAND, K, OP)
            else:
                XRES, CK, IK, AK = self.Milenage.f2345(RAND, K)
            RES, Kc = conv_102_C2(XRES), conv_102_C3(CK, IK)
        elif ALG == 4:
            # TUAK, adapted to 2G
            if OP is not None:
                # which is actually TOP, for TUAK
                XRES, CK, IK, AK = self.TUAK.f2345(RAND, K, OP)
            else:
                XRES, CK, IK, AK = self.TUAK.f2345(RAND, K)
            RES, Kc = conv_102_C2(XRES), conv_102_C3(CK, IK)
        else:
            # COMP128
            if ALG == 1:
                RES, Kc = comp128v1(K, RAND)
            elif ALG == 2:
                RES, Kc = comp128v2(K, RAND)
            elif ALG == 3:
                RES, Kc = comp128v3(K, RAND)
            else:
                # invalid ALG
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
        or None if the IMSI is not defined in the db or does not support Milenage or TUAK
        
        RAND can be passed as argument
        '''
        # lookup db for authentication Key and counter for IMSI
        try:
            K_ALG_SQN_OP = self.db[IMSI]
        except Exception:
            self._log('WNG', '[make_3g_vector] IMSI %s not present in AuC.db' % IMSI)
            return None
        if len(K_ALG_SQN_OP) == 4:
            K, ALG, SQN, OP = K_ALG_SQN_OP
        else:
            K, ALG, SQN = K_ALG_SQN_OP
            OP = None
        #
        if SQN == -1:
            # Milenage / TUAK not supported
            self._log('WNG', '[make_3g_vector] IMSI %s does not support Milenage / TUAK' % IMSI)
            return None
        #
        # increment SQN counter in the db
        K_ALG_SQN_OP[2] += 1
        self._save_required = True
        #
        # pack SQN from integer to a 48-bit buffer
        SQNb = pack('>Q', SQN)[2:]
        #
        # generate challenge if necessary
        if RAND is None:
            RAND = genrand(16)
        #
        if ALG == 0:
            # compute Milenage functions
            if OP is not None:
                XRES, CK, IK, AK = self.Milenage.f2345( K, RAND, OP )
                MAC_A            = self.Milenage.f1( K, RAND, SQNb, AMF, OP )
            else:
                XRES, CK, IK, AK = self.Milenage.f2345( K, RAND )
                MAC_A            = self.Milenage.f1( K, RAND, SQNb, AMF )
        elif ALG == 4:
            # compute TUAK functions
            if OP is not None:
                XRES, CK, IK, AK = self.TUAK.f2345( K, RAND, OP )
                MAC_A            = self.TUAK.f1( K, RAND, SQNb, AMF, OP )
            else:
                XRES, CK, IK, AK = self.TUAK.f2345( K, RAND )
                MAC_A            = self.TUAK.f1( K, RAND, SQNb, AMF )
        else:
            # invalid ALG
            return None
        #
        AUTN = xor_buf( SQNb, AK ) + AMF + MAC_A
        #
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
        or None if the IMSI is not defined in the db or does not support Milenage or TUAK
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
            K_ALG_SQN_OP = self.db[IMSI]
        except Exception:
            self._log('WNG', '[make_4g_vector] IMSI %s not present in AuC.db' % IMSI)
            return None
        if len(K_ALG_SQN_OP) == 4:
            K, ALG, SQN, OP = K_ALG_SQN_OP
        else:
            K, ALG, SQN = K_ALG_SQN_OP
            OP = None
        #
        if ALG not in (0, 4):
            # Milenage / TUAK not supported
            self._log('WNG', '[make_4g_vector] IMSI %s does not support Milenage or TUAK' % IMSI)
            return None
        #
        # increment SQN counter in the db
        if SQN >= 0:
            K_ALG_SQN_OP[2] += 1
            self._save_required = True
        #
        # pack SQN from integer to a 48-bit buffer
        SQNb = pack('>Q', SQN)[2:]
        #
        # generate challenge
        if RAND is None:
            RAND = genrand(16)
        #
        if ALG == 0:
            # compute Milenage functions
            if OP is not None:
                XRES, CK, IK, AK = self.Milenage.f2345( K, RAND, OP )
                MAC_A            = self.Milenage.f1( K, RAND, SQNb, AMF, OP )
            else:
                XRES, CK, IK, AK = self.Milenage.f2345( K, RAND )
                MAC_A            = self.Milenage.f1( K, RAND, SQNb, AMF )
        else:
            # ALG == 4, compute TUAK functions
            if OP is not None:
                XRES, CK, IK, AK = self.TUAK.f2345( K, RAND, OP )
                MAC_A            = self.TUAK.f1( K, RAND, SQNb, AMF, OP )
            else:
                XRES, CK, IK, AK = self.TUAK.f2345( K, RAND )
                MAC_A            = self.TUAK.f1( K, RAND, SQNb, AMF )
        #
        SQN_X_AK = xor_buf( SQNb, AK )
        AUTN = SQN_X_AK + AMF + MAC_A
        # convert to LTE master key
        KASME = conv_401_A2(CK, IK, SN_ID, SQN_X_AK)
        #
        # return auth vector
        self._log('DBG', '[make_4g_vector] IMSI %s, SQN %i, SN_ID %s: RAND %s, XRES %s, AUTN %s, KASME %s'\
                  % (IMSI, SQN, hexlify(SN_ID).decode('ascii'), hexlify(RAND).decode('ascii'), 
                     hexlify(XRES).decode('ascii'), hexlify(AUTN).decode('ascii'), 
                     hexlify(KASME).decode('ascii')))
        return RAND, XRES, AUTN, KASME
    
    def make_5g_vector(self, IMSI, SNName, AMF=b'\x80\x00', RAND=None):
        """
        return a 5G authentication vector "quadruplet":
        RAND [16 bytes], XRES* [8 bytes], AUTN [16 bytes], KAUSF [32 bytes]
        or None if the IMSI is not defined in the db or does not support Milenage or TUAK
        or SNName is invalid or not allowed
        
        SNName is the serving network name, ascii-encoded bytes buffer
        RAND can be passed as argument
        """
        if not isinstance(SNName, bytes_types) or not 32 <= len(SNName) <= 255:
            self._log('WNG', '[make_5g_vector] SNName invalid, %s' % SNName.decode('ascii'))
            return None
        elif self.PLMN_FILTER is not None:
            # extract MCC, MNC from SNName (e.g. "5G:mnc012.mcc345.3gppnetwork.org")
            snname_parts = SNName.split(':')[1].split('.')
            mcc, mnc =  snname_parts[1][3:], snname_parts[0][3:]
            if mcc + mnc not in self.PLMN_FILTER:
                self._log('WNG', '[make_5g_vector] SNName not allowed, %s' % SNName.decode('ascii'))
                return None
        #
        # lookup db for authentication Key and counter for IMSI
        try:
            K_ALG_SQN_OP = self.db[IMSI]
        except Exception:
            self._log('WNG', '[make_5g_vector] IMSI %s not present in AuC.db' % IMSI)
            return None
        if len(K_ALG_SQN_OP) == 4:
            K, ALG, SQN, OP = K_ALG_SQN_OP
        else:
            K, ALG, SQN = K_ALG_SQN_OP
            OP = None
        #
        if ALG not in (0, 4):
            # Milenage / TUAK not supported
            self._log('WNG', '[make_4g_vector] IMSI %s does not support Milenage or TUAK' % IMSI)
            return None
        #
        # increment SQN counter in the db
        if SQN >= 0:
            K_ALG_SQN_OP[2] += 1
            self._save_required = True
        #
        # pack SQN from integer to a 48-bit buffer
        SQNb = pack('>Q', SQN)[2:]
        #
        # generate challenge
        if RAND is None:
            RAND = genrand(16)
        #
        if ALG == 0:
            # compute Milenage functions
            if OP is not None:
                XRES, CK, IK, AK = self.Milenage.f2345( K, RAND, OP )
                MAC_A            = self.Milenage.f1( K, RAND, SQNb, AMF, OP )
            else:
                XRES, CK, IK, AK = self.Milenage.f2345( K, RAND )
                MAC_A            = self.Milenage.f1( K, RAND, SQNb, AMF )
        else:
            # ALG == 4, compute TUAK functions
            if OP is not None:
                XRES, CK, IK, AK = self.TUAK.f2345( K, RAND, OP )
                MAC_A            = self.TUAK.f1( K, RAND, SQNb, AMF, OP )
            else:
                XRES, CK, IK, AK = self.TUAK.f2345( K, RAND )
                MAC_A            = self.TUAK.f1( K, RAND, SQNb, AMF )
        #
        SQN_X_AK = xor_buf( SQNb, AK )
        AUTN = SQN_X_AK + AMF + MAC_A
        # convert to AUSF master key
        KAUSF = conv_501_A2(CK, IK, SNName, SQN_X_AK)
        XRESstar = conv_501_A4(CK, IK, SNName, RAND, XRES)
        #
        # return auth vector
        self._log('DBG', '[make_5g_vector] IMSI %s, SQN %i, SNName %s: RAND %s, XRES* %s, AUTN %s, KAUSF %s'\
                  % (IMSI, SQN, hexlify(SNName).decode('ascii'), hexlify(RAND).decode('ascii'), 
                     hexlify(XRESstar).decode('ascii'), hexlify(AUTN).decode('ascii'), 
                     hexlify(KAUSF).decode('ascii')))
        return RAND, XRESstar, AUTN, KAUSF
    
    def synch_sqn(self, IMSI, RAND, AUTS):
        """
        synchronize the local counter SQN with AUTS provided by the USIM
        in response to a given 3G or 4G authentication challenge (RAND, AMF)
        
        return 0 on successful synch, 1 on unsuccessful synch due to invalid AUTS
        or None if the IMSI is not defined in the db
        """
        # lookup db for authentication Key and counter for IMSI
        try:
            K_ALG_SQN_OP = self.db[IMSI]
        except Exception:
            self._log('WNG', '[synch_sqn] IMSI %s not present in AuC.db' % IMSI)
            return None
        if len(K_ALG_SQN_OP) == 4:
            K, ALG, SQN, OP = K_ALG_SQN_OP
        else:
            K, ALG, SQN = K_ALG_SQN_OP
            OP = None
        #
        if ALG not in (0, 4):
            # Milenage not supported
            self._log('WNG', '[make_3g_vector] IMSI %s does not support Milenage or TUAK' % IMSI)
            return None
        #
        # 33.102, section 6.3.3, for resynch, AMF is always null (0x0000)
        AMF = b'\0\0'
        #
        if ALG == 0:
            # compute Milenage functions
            if OP is not None:
                AK      = self.Milenage.f5star( K, RAND, OP )
                SQN_MS  = xor_buf( AUTS[0:6], AK )
                MAC_S   = self.Milenage.f1star( K, RAND, SQN_MS, AMF, OP )
            else:
                AK      = self.Milenage.f5star( K, RAND )
                SQN_MS  = xor_buf( AUTS[0:6], AK )
                MAC_S   = self.Milenage.f1star( K, RAND, SQN_MS, AMF )
        else:
            # ALG == 4, compute TUAK functions
            if OP is not None:
                AK      = self.TUAK.f5star( K, RAND, OP )
                SQN_MS  = xor_buf( AUTS[0:6], AK )
                MAC_S   = self.TUAK.f1star( K, RAND, SQN_MS, AMF, OP )
            else:
                AK      = self.TUAK.f5star( K, RAND )
                SQN_MS  = xor_buf( AUTS[0:6], AK )
                MAC_S   = self.TUAK.f1star( K, RAND, SQN_MS, AMF )
        #
        # unmask SQN
        SQN_MSi = unpack('>Q', b'\0\0' + SQN_MS)[0]
        #
        self._log('DBG', '[synch_sqn] USIM resynchronization, SQN_MS %i, MAC_S %s'\
                  % (SQN_MSi, hexlify(MAC_S).decode('ascii')))
        #
        # authenticate the USIM
        if MAC_S != AUTS[6:14]:
            self._log('WNG', '[synch_sqn] IMSI %s, USIM authentication failure' % IMSI)
            return 1
        #
        # resynchronize local SQN value
        K_ALG_SQN_OP[2] = SQN_MSi + self.SQN_SYNCH_STEP
        self._save_required = True
        self._log('DBG', '[synch_sqn] IMSI %s, SQN resynchronized to %i' % (IMSI, K_ALG_SQN_OP[2]))
        return 0
    
    def sidf_unconceal(self, hnkid, ephpubk, cipht, mac):
        """
        unconceal the cipher text `cipht` according to ECIES profile A or B (which
        is implicitly depending on `hnkid`).
        Use the home network private key index `hnkid`, ephemeral public key 
        `ephpubk`, after verifying the `mac`. All parameters are part of the
        SUCI.
        
        return None on error or the unconceal clear-text value bytes buffer (i.e.
        the clear-text 5G subscriber identity)
        """
        if hnkid not in self._SIDF_ECIES or not 32 <= len(ephpubk) <= 33 or len(mac) != 8:
            self._log('WNG', '[sidf_unconceal] invalid parameter')
            return None
        #
        try:
            cleart = self._SIDF_ECIES[hnkid].unprotect(ephpubk, cipht, mac)
        except Exception as err:
            self._log('ERR', '[sidf_unconceal] EC processing error: %s' % err)
            return None
        else:
            self._log('DBG', '[sidf_unconceal] SUCI ciphertext %s decrypted to %s'\
                      % (hexlify(cipht).decode('ascii'), hexlify(cleart).decode('ascii')))
            return cleart


def test():
    AuC.OP  = b'ffffffffffffffff'
    AuC.TOP = b'ffffffffffffffffffffffffffffffff'
    auc  = AuC()
    imsi = '001010000000001'
    rand = 16 * b'\x00'
    K    = unhexlify('0123456789abcdef0123456789abcdef')
    #
    # comp128-1
    auc.db[imsi] = [K, 1, -1]
    assert(
        auc.make_2g_vector(imsi, rand) == (
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            b'2\xae\x086',
            b'5\x934\x86\x18\xa0\x94\x00')
            )
    #
    # comp128-2
    auc.db[imsi] = [K, 2, -1]
    assert(
        auc.make_2g_vector(imsi, rand) == (
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            b'2a!)',
            b'a]\xe3+\xe7\xdd \x00')
            )
    #
    # comp128-3
    auc.db[imsi] = [K, 3, -1]
    assert(
        auc.make_2g_vector(imsi, rand) == (
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            b'2a!)',
            b'a]\xe3+\xe7\xdd#\xba')
            )
    auc.db[imsi] = [K, 0, 0]
    #
    # milenage
    assert(
        auc.make_2g_vector(imsi, rand) == (
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x80\x9a\x82\x0e',
            b'd\xc1\xeb\x0c\xebRz\x13')
            )
    assert(
        auc.make_3g_vector(imsi, b'\x00\x00', rand) == (
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            b'@*\x8f\xc0\x81\xcd8f',
            b"\x97e\x98\xdb\xc9\x01\x00\x00\xcd\x16Nu\xb6'GH",
            b"/\xff\x18\xbc\x1d'\x12\x12\xa8\x80K\x1e\xbf\xe5O\xed",
            b'U\xd6\t\x00\x9eu\xfa\xdbS-U\xc8\x99<G@')
            )
    assert(
        auc.make_4g_vector(imsi, b'\x00\xf1\x10', b'\x80\x00', rand) == (
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            b'@*\x8f\xc0\x81\xcd8f',
            b'\x97e\x98\xdb\xc9\x00\x80\x00:\x07~5\xf9\x0f\xd5\xda',
            b'@\xf0\x07"H\x96\x88\xe4\x8d\\\x86f,\xaaJQc\xc1/\x99[\xd8\xaa\xd4i\xd6{\xf8\x1c\xfc\x8d9')
            )
    assert(
        auc.make_5g_vector(imsi, b'5G:mnc001.mcc001.3gppnetwork.org', b'\x80\x00', rand) == (
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x02YS4d\xdb\xbc\xcfa\xab\x9c\x8a\xda\xcf\xacR',
            b'\x97e\x98\xdb\xc9\x03\x80\x00\xb2\x9c\n\xf4\xe5\x8a\x10x',
            b'\xaal4h\x00W\x82\xbd\x1f\xf6\x91\x83\xd2\xcc\x03\x8d\xddk7\xf6\xce\xf8i\xd8\xd3\xa9\x1b\x8c\xba\xc9\r\xe9')
            )
    assert(
        auc.synch_sqn(imsi, rand, b'Qx\xcb4\xa3Tf^\xa2\xaeN5;$') == 0
            )
    #
    # TUAK
    auc.db[imsi] = [K, 4, 0]
    assert(
        auc.make_2g_vector(imsi, rand) == (
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x96\xb5c\xa1',
            b'\x9bk\x97\xb5\xfd\xe5\xc1}')
            )
    assert(
        auc.make_3g_vector(imsi, b'\x00\x00', rand) == (
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x12p#\x8aKHQ]',
            b'o\x1b6:\x9e\xeb\x00\x00K\x9c#\x9f\x80\xaf\xaaC',
            b'J\x91\xf8\xc7\xd9x;\xe1\xa6\x10b~o\xe9U\x8d',
            b'_U\xd5\xf1\xaa\x95\xcf\x86\xea(\xb5\xad\xb5\x96e\xd8')
            )
    assert(
        auc.make_4g_vector(imsi, b'\x00\xf1\x10', b'\x80\x00', rand) == (
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x12p#\x8aKHQ]',
            b'o\x1b6:\x9e\xea\x80\x00\x8c\xf4\xcfz\xe3\x91\xd7W',
            b"q\x83Z\xbel\x96%^\x81f\xcf\xab)\x07B\x93\nsl\xae'oAULu\x15\xb1\x12\x9f\x1ap")
            )
    assert(
        auc.make_5g_vector(imsi, b'5G:mnc001.mcc001.3gppnetwork.org', b'\x80\x00', rand) == (
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x0bzY,\xd60\xd0X\xfe\xac\xf2DQ\xb07<',
            b'o\x1b6:\x9e\xe9\x80\x00V\x92\xae\x87\xab@\xbe\x8b',
            b'\x87\x8d\x03\x95\xe4\x8b\x17\xef%CM_U4\x05`\xc6\xac\xa4w\xc4\xfaH\xdfS\x84\x01\xa3-9\xf1\x91')
            )
    assert(
        auc.synch_sqn(imsi, rand, b'h\xe4\xf2T\xc7\xa9v\xe1Gy\xcf,#\x9f') == 0
            )
    #
    # SIDF
    # set a HN private key for profile A
    AuC.SIDF_ECIES_K[0] = ('A', b'0\xfd\xa5\x0321y\xbe\xb2#\x8d\xbb\x85\x84\xe4\xb3\xffb\xb9\xdd\x85\xf3\x18N\x89!7\x15\xd3\x7f2X')
    auc = AuC()
    assert(
        auc.sidf_unconceal(
            0,
            b'\x82\xcb\xb7\xb5\x00u\xc5/\xbd\xd8\xa4.\xbc|\x9ad,\x17\xa8(\xfdu\xd1\x7f\x01[::\xea\x97\xfay',
            b'\xb8\xc3c{\xe4',
            b'\xac\xeeXw\xca!\x04\xc6') == b'\x00\x00\x00\x00\x10'
            )

