# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.6
# *
# * Copyright 2023. Benoit Michau. P1Sec.
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
# * File Name : test/test_crypto.py
# * Created : 2023-04-07
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from timeit     import timeit
from binascii   import unhexlify
#
from pycrate_core.elt     import _with_json
from pycrate_crypto.IKEv2 import IKEv2, PayEncr, IKEv2TransENCR, IKEv2TransAUTH


ikev2_pdu = (
    '864330ac30e6564d00000000000000002120220800000000000001c9220000300000002c010100040300000c0100000c800e0080030000080200000203000008030000020000000804000002280000880002000003dcf59a29057b5a49bd558c9b147a110eedffe5ea2d12c21e5c7a5f5e9c99e3d1d300243c89731e6c6d63417b33faaf5ac726e8b6f8c3b52a14ebecd56f1bd95b2832849e26fc59eef14e385f55c21be8f6a3fbc555d73592862400628beace23f047afaaf861e45c42ba5ca14a526ed8e8f1b974aee4d19c9fa59bf0d7db552b0000444ca7f39bcd1dc20179faa2e472e061c44561e6492db396aec92cdb5421f4984f72d24378ab80e46c01786ac46445bca81f56bcedf9b5d821954171e90eb43c4e2b000017434953434f2d44454c4554452d524541534f4e2b00003b434953434f28434f505952494748542926436f7079726967687420286329203230303920436973636f2053797374656d732c20496e632e29000013434953434f2d4752452d4d4f4445022900001c010040047e576cc013d40543a2e8777d003468a5b1890c582b00001c0100400552644d87d47c2d4423bd37e448a9f5170181cb8a000000144048b7d56ebce88525e7de7f00d6c2d3',
    '864330ac30e6564d8329cc09a2c7d7e02120222000000000000001c9220000300000002c010100040300000c0100000c800e00800300000802000002030000080300000200000008040000022800008800020000ae4bfcd2c14f01696034ccab90c1f82b60a2cb4e053c82efbe08dd29562b27b2bacd7aad29e81d21f1df503f7500168d13236ae058eaee8d9128eade2cd4dd491497a137a620c7b9812f6ca0955b4a18b96684c86880573bbc39d5163ebfa04d2615200b3a6588afe4f2b72a0bc3ef35cb6c19325ea4f1a81f798ddc0d17e47f2b000044352bbc444c4c77ca2bf488b5b20600989fa307d9a74fd6f9ec0b244bc3398bcf3b0ab2ed819c812ecd67a05cb27a5ac9dc77cfc4151f66701875846626ee6b702b000017434953434f2d44454c4554452d524541534f4e2b00003b434953434f28434f505952494748542926436f7079726967687420286329203230303920436973636f2053797374656d732c20496e632e29000013434953434f2d4752452d4d4f4445022900001c0100400457258553bb61856970a95cedca1e783dfe5215142b00001c010040056684cd36f56618786a9c94abe738123a4be1102c000000144048b7d56ebce88525e7de7f00d6c2d3',
    ('864330ac30e6564d8329cc09a2c7d7e02e20230800000001000000fc2b0000e0475423ac61a80d26af7da2156cfe2299ab62a7211f67d62a23ac239f537a4004770d4b1adb9ac33929d18fc134d07593cd57cfe7fb8cfb3485804e1d4bf71a5ba0a88675606e4c6349f12419f4e4b1321a1b86576fd87c32ff868378bb3a40e2e0bdd0abcfe68e0d6eba223cafc2e7431d37ce00a5dde230e2f10e33de81e6c41f33acfcc333dbda0fa26591a49fca0086507f8a562d99e8c98cadc9e62b02c08ed9059e0b949901ecd99714a2f65128ed28cd70e1cd8185cec1d48fc1402d96bc727487023aa237918728fcf1a6fc12a88a2f362bcdbbdc9e1a7a3b', IKEv2TransENCR.ENCR_AES_CBC, IKEv2TransAUTH.AUTH_HMAC_SHA1_96),
    ('864330ac30e6564d8329cc09a2c7d7e02e20232000000001000000ec2b0000d05ec738b9959f1dc97f2f1cf870ce74da74955b63a4371e65f81f7a30ad83ff19854299e489fa284108dcf4b88938131582e174dd4ff8273569201b1972a547b9551c48703ca1bcc33df210fa9c7ae677ac4e0ec6e6d63a4ad2d1337f8a1d2bfbb8c125b274ffdd7599b7eb33bc3d2a41d8ad3710c767a85ec8507b489ebead0b80c4c598b5fae711fb27da46b49b33f86e44ace3186fb1bb51391eb13ae41eb52ebcb2c2bfcaaaf6baaaff93176cac041846d1086da27bc840f2577a3aa852da9cb2564893cff72302eae2f5', IKEv2TransENCR.ENCR_AES_CBC, IKEv2TransAUTH.AUTH_HMAC_SHA1_96),
    'a732fc30477d5ae700000000000000002120220800000000000001fc2200005c0200002c010100040300000c0100000c800e00100300000802000002030000080300000200000008040000020000002c020100040300000c01000014800e00100300000802000005030000080300000c000000080400001328000108000e0000dfc4079ddc65ff7ca8f0b9fc4ae61f89b353bba573cb6b68b1fcc96c3186473860e65ca5e9a30bddc813650ba1683f41e362bb97c31a0e932171940486b8f5129dcff02df9cbfd29b9c2987eb6d2c13fdf979cf5e03d084ede019bd78cec693d6c2e80af40fdb9defd7728b544edd9880fca035b4eb1412f9fc61cd217e069bd72189ebe7b0199fbdb32302e008e250ad308bc93a6e89bdcff5813d76b261298455d2c78c4d994c05d15455fef8e7f7d1b6f7ddc74898aa2fe6381eb9168efa657b1d767fa2156558f184c91a5d250cab773bdcda65735768406acc23b41401067eccf5a211f0150e2a27d038ac3b5f03267529ef01bd26deb26132c998ea3eb29000044cd9be9837d8825f8f4892cd321285008920c2c039f96b19ad29ed2975016f388f9b8b98f8499cb1e6d177bdb9fd2dd17ab294eb4827b62448c7b36d2797019052900001c01004004b562cfed59d1124eaa7029e898fdcf4bab303cd10000001c01004005af8a9ba2ba54e2bff77997a076d3f7dc9ec1b12d',
    )


def test_ikev2(ikev2_pdu=ikev2_pdu):
    m = IKEv2()
    for pdu in ikev2_pdu:
        #
        if isinstance(pdu, tuple) and len(pdu) == 3:
            PayEncr.set_alg(*pdu[1:])
            pdu = pdu[0]
        pdu = unhexlify(pdu)
        #
        m.from_bytes(pdu)
        v = m.get_val()
        m.reautomate()
        assert( m.get_val() == v )
        assert( m.to_bytes() == pdu )
        m.set_val(v)
        assert( m.get_val() == v )
        assert( m.to_bytes() == pdu )
        #
        if _with_json:
            t = m.to_json()
            m.from_json(t)
            assert( m.get_val() == v )


def test_perf_crypto():
    
    print('[+] IKEv2 message decoding and re-encoding')
    Ta = timeit(test_ikev2, number=80)
    print('test_ikev2: {0:.4f}'.format(Ta))
    
    print('[+] test_crypto total time: {0:.4f}'.format(Ta))


if __name__ == '__main__':
    test_perf_crypto()

