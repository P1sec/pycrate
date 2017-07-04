# -*- coding: UTF-8 -*-

# 1) convert all 36XYZ-$release.doc files to text files in utf-8 format with MS Office
# 2) use this script to extract all ASN.1 modules

import codecs
import re

dirpath = './'
path = dirpath + '29078-Rel-12_modules.txt'

# ASN.1 modules are described within specific sections
# no extraction of ECN modules
sections = [
    '-- 5.1	Data types',
    '-- 5.2	Error types',
    '-- 5.3	Operation codes',
    '-- 5.4	Error codes',
    '-- 5.5	Classes',
    '-- 5.6	Object IDentifiers (IDs)',
    '-- 5.7	User Abort Data',
    '-- 6.1.1	Operations and arguments',
    '-- 6.1.2.1	gsmSSF/gsmSCF ASN.1 module',
    '-- 6.2.1	gsmSCF/gsmSRF operations and arguments',
    '-- 6.2.2.1	gsmSRF/gsmSCF ASN.1 modules',
    '-- 7.1	SMS operations and arguments',
    '-- 7.2.1	smsSSF/gsmSCF ASN.1 module',
    '-- 8.1	gsmSCF/gprsSSF operations and arguments',
    '-- 8.1.1	GPRS Reference Number',
    '-- 8.1.2	Operation timers'
    ]

# for RRC, this re works fine as there is no OID when a module is declared
module_def = re.compile('^([A-Z][a-zA-Z0-9\-]{0,})\s{1,}\{')

def main():
    
    fd = codecs.open(path, 'r', 'utf-8')
    speclines = fd.readlines()
    fd.close()
    #print(len(speclines))
    
    inside, start = False, False
    module = []
    module_name = None
    
    for line in speclines:
        if line[:-2] in sections:
            if inside:
                raise(Exception('ASN.1 extraction failed: %s' % line))
            inside, start = True, True
        elif inside and re.match('^END($|\s)', line):
            module.append(line)
            inside = False
            print('%s.asn' % module_name)
            fd = codecs.open(dirpath + module_name + '.asn', 'w', 'utf-8')
            fd.write( ''.join(module) )
            fd.close()
            module = []
            module_name = None
        else:
            if inside:
                #print('inside')
                if start:
                    #print('start')
                    m = module_def.match(line)
                    if m:
                        module_name = m.group(1)
                        start = False
                        start = False
                        #print(module_name)
                    elif not re.match('^\s{1,}$', line) and not line[:2] == '--':
                        start = False
                # inside a module: storing the line
                module.append(line)
    
    print('> extraction done')
    return 0

if __name__ == '__main__':
    main()

