# -*- coding: UTF-8 -*-

# 1) convert all 36XYZ-$release.doc files to text files in utf-8 format with MS Office
# 2) use this script to extract all ASN.1 modules

import codecs
import re

import sys
if sys.platform == 'win32':
    eollen = 2
else:
    eollen = 1


dirpath = './'
path = dirpath + '36413-f71.txt'

# ASN.1 modules are described within specific sections
sections = [
    '9.3.2	Elementary Procedure Definitions',
    '9.3.3	PDU Definitions',
    '9.3.4	Information Element Definitions',
    '9.3.5	Common Definitions',
    '9.3.6	Constant Definitions',
    '9.3.7	Container Definitions',
    'B.2	ASN.1 definition'
    ]

module_def = re.compile('^([A-Z][a-zA-Z0-9\-]{0,})\s{0,}')

def main():
    
    fd = codecs.open(path, 'r', 'utf-8')
    speclines = fd.readlines()
    fd.close()
    #print(len(speclines))
    
    inside, start = False, False
    module = []
    module_name = None
    
    for line in speclines:
        if line[:-eollen] in sections:
            if inside:
                raise(Exception('ASN.1 extraction failed: %s' % line))
            inside, start = True, True
        elif line[:-eollen] == 'END':
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
                        #print(module_name)
                    elif not re.match('^\s{1,}$', line) and not line[:2] == '--':
                        start = False
                # inside a module: storing the line
                module.append(line)
    
    print('> extraction done')
    return 0

if __name__ == '__main__':
    main()

