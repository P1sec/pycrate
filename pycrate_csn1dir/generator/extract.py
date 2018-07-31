# -*- coding: UTF-8 -*-

import os
import sys
import codecs
import re
from pycrate_csn1_new.utils import *

# sections of TS 44.060 with CSN.1 modules : 11 and 12, extracted manually as txt
# sections of TS 44.018 with CSN.1 modules : 9 and 10, extracted manually
# sections of TS 24.008 with CSN.1 modules : 10, extracted manually 

# method:
#--------
# scan all lines 1 by 1
# identify section V.X.Y or W.X.Y to remind main section name
# search assignment "::="
# extract block from "::=" to ";"
# remove comment after "--"

# warnings:
#----------
#
# 44.060: few quirks have been corrected in the .txt files provided here:
# 0) commented out the definition of < padding bits > as it is built-in in the compiler
# 1) < PBCCH Description struct 2 > with some invisible chars
# 2) < EGPRS PACKET CHANNEL REQUEST message content for ‘PEO One Phase Access Request’ > with those 2 unacceptable chars
# 3) some CSN.1 comments introduced in front of the end of definition mark ";" have been removed :
# < PSI3 quater message content >
# < Fixed Uplink Allocation struct >
# < PUANCR Fixed Uplink Allocation struct >
# 4) commented out the definition in 11.1.3.1 which overwrites some other definition for nothing useful
# 5) renamed duplicated definitions for EC-PACCH:
# < Distribution message on EC-PACCH >
# < Distribution contents on EC-PACCH >
# < Non-distribution message on EC-PACCH >
# < Default downlink message content >
# 6) in 11.2.28b, changed the definition to < Packet DBPSCH Uplink Ack/Nack Type 2 message content > to avoid overwrite
# 7) some missing end of definition ";":
# < Global Packet Timing Advance IE >
#
# 
# 44.018:
# 0) some NAS fields included into descriptions are noted <bit string> which is greedy,
# replaced them with a custom <NAS Type4 LV> struct
# <Group Channel Description>
# <Paging Information>
# <new Group Channel Description>
# <SI10bis Neighbour Cell Info>
# 1) renamed duplicated definitions for all EC PACKET CHANNEL REQUEST: CC1, CC2, CC3 and CC4
# 2) removed comma from < Frequency Parameters, before time >
# 3) changed invalid assignment
# NT/N Rest Octets ::=
# to 
# < NTN Rest Octets > ::=
# 4) commented out { ... } inclusion of master object in:
# < P1 Rest Octets >
# <P2 Rest Octets >
# 5) changed MSG_TYPE::= {...} to MSG_TYPE := {...} in 10.5.2.52 (3 times)
# 6) changed expr related to length ref in:
# < COMPACT Neighbour Cell params struct >
# < EC Neighbour Cell Description struct >
# <Enhanced Measurement report>
# 7) changed all mis-encoded "" to "{"
# 8) added ";" at the end of <VBS/VGCS RECONFIGURE>, <VBS/VGCS RECONFIGURE2>
# and few others that I don't remember
#
# 
# 24.018:
# 0) changed some field names:
#  < 8-PSK Struct> to < 8PSK Struct>
#  < (EC-)PCH monitoring support: bit(2)> to < PCH monitoring support: bit(2)>
# 1) changed quite lots of syntax errors for the "Receive N‑PDU Number list value"
# 2) missing ";" after < 8PSK Struct>
# 3) changed some "bit string (...)" into "bit (...)"
# 4) commented out "<Spare bits>"


# local path and specifications name
PATH     = os.path.dirname(os.path.abspath( __file__ )) + os.sep
SPECS    = ['24008', '44018', '44060']

# regexp
RE_SECT = re.compile('(9|10|11|12)\.([0-9]{1,}[a-zA-Z]{0,})(\.[0-9]{1,}[a-zA-Z]{0,}){0,2}\t[a-zA-Z0-9]{1,}')
RE_ASSI = re.compile('::=')
RE_CMT  = re.compile('--')
RE_END  = re.compile(';')
RE_NAME = SYNT_RE_NAME
RE_ITEM = re.compile('<\s{0,}[a-zA-Z0-9]{1,}')


def create_csn_file(csndef, specpath, spec, title, warn=False):
    assert( len(csndef) >= 1 and title )
    #print(csndef)
    # identify the main CSN.1 struct name (1st assignment)
    csntxt, names, main_name = [], set(), ''
    for grp in csndef:
        assert( len(grp) >= 1 )
        dup = set()
        m_name = RE_NAME.match(grp[0])
        if not m_name:
            print('[ERR] %r' % grp)
            assert()
        name = m_name.group(1).strip()
        if name in names:
            dup.add(name)
        else:
            names.add(name)
        if not main_name:
            main_name = name
        csntxt.append( ''.join(grp) )
    # create the csn file
    p_name = pythonize_name(main_name)
    fd = open(PATH + specpath + os.sep + p_name + '.csn', 'w')
    fd.write('-- %s\n-- %s\n-- %s\n\n' % (spec, title, main_name))
    for txt in csntxt:
        fd.write(txt)
        fd.write('\n')
    fd.close()
    # check for duplication
    print('[+] created: %s.csn' % p_name)
    print('    %i definition(s)' % len(csntxt))
    if warn and dup:
        print('[WNG] duplicated objects: %r' % list(dup))
    return len(csntxt), p_name


def harmonize_line(line):
    # some .doc to .txt and other MS Word oddities inconsistencies
    line = re.sub('\:\s{0,}\:\s{0,}=', '::=', line)
    line = line.replace('\xa0', ' ')
    line = line.replace('\uf07b', '{')
    return line


def pythonize_line(line):
    line = re.sub(' {2,}', ' ', line)
    #line = line.replace('\t', '    ')
    #line = re.sub('\s', ' ', line)
    return line


def process(fn, spec, warn=False):
    dbg = False
    #
    fd = open(PATH + fn)
    lines = fd.readlines()
    fd.close()
    #
    print('[o] %s, %s: processing' % (fn, spec))
    #
    csndef, csnin, title, num, names = [], False, '', 0, set()
    for line in lines:
        line = harmonize_line(line)
        m_sect = RE_SECT.match(line)
        m_assi = RE_ASSI.search(line)
        m_cmt  = RE_CMT.search(line)
        m_end  = RE_END.search(line)
        #
        if not csnin and m_sect:
            # new section
            assert( m_assi is None and m_cmt is None )
            if csndef:
                n, mn = create_csn_file(csndef, fn[:5], spec, title, warn)
                num += n
                if warn and mn in names:
                    print('[WNG] duplicated csn modules: %s.csn' % mn)
                else:
                    names.add(mn)
                csndef.clear()
            #
            title = re.sub('\s', ' ', line[:-1])
            if dbg:
                print('> %s' % title)
        #
        elif title and not csnin and m_assi:
            if not m_cmt or m_assi.end() < m_cmt.start():
                # start of CSN.1 assignment
                csnin = True
                csndef.append( [pythonize_line(line)] )
                if m_end:
                    if not m_cmt or m_end.end() < m_cmt.end():
                        # single line definition
                        csnin = False
        #
        elif title and csnin and m_end:
            if not m_cmt or m_end.end() < m_cmt.end():
                # end of CSN.1 assignment
                csnin = False
                assert( csndef )
                csndef[-1].append(pythonize_line(line))
            elif warn and m_cmt.end() < m_end.start():
                # it happens that a comment is inserted before the ";"
                print('[WNG] suspicious CSN.1 ";" after comment: %s' % line)
        #
        elif title and csnin:
            assert( csndef )
            csndef[-1].append(pythonize_line(line))
            if m_cmt:
                # in case of potential missing CRLF between the cmt
                # and another CSN.1 item
                m_item = RE_ITEM.search(line)
                if warn and m_item and m_item.start() > m_cmt.end():
                    print('[WNG] suspicious CSN.1 "< ... >" after comment: %s'\
                          % line)
    #
    if title and csndef:
        n, mn = create_csn_file(csndef, fn[:5], spec, title, warn)
        num += n
        if warn and mn in names:
            print('[WNG] duplicated csn modules: %s.csn' % mn)
        else:
            names.add(mn)
    print('[o] %s, %s: done, %i definitions' % (fn, spec, num))


def search_specs(specfilt):
    fns = os.listdir(PATH)
    ret = []
    for fn in fns:
        if fn[:5] in specfilt and fn[-4:] == '.txt':
            # found a text file ready for extraction
            spec = 'TS %s.%s - %s' % (fn[:2], fn[2:5], fn[6:9])
            ret.append((fn, spec))
            # ensure a corresponding directory exists
            if fn[:5] not in fns:
                print('[+] creating dir: %s' % fn[:5])
                os.makedirs(PATH + fn[:5])
    return ret


def usage():
    print('extract.py: extract CSN.1 definitions from 3GPP specifications')
    print('    specs: %r' % (SPECS, ))
    print('')
    print('options:')
    print('    -w / --warn: print warnings in case of potential errors during the extraction')
    print('')


if __name__ == '__main__':
    specs = search_specs(SPECS)
    if len(sys.argv) == 2 and sys.argv[1] in ('-w', '--warn'):
        warn = True
    elif len(sys.argv) > 1:
        usage()
        sys.exit(0)
    else:
        warn = False
    for fn, spec in specs:
        process(fn, spec, warn)
    sys.exit(0)

