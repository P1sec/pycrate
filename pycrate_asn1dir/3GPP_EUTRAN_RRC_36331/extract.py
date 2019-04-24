# -*- coding: UTF-8 -*-

# 1) convert the 36331-$release.doc file to text files in utf-8 format with MS Office
# 2) use this script to extract all LTE RRC ASN.1 modules

import codecs
import re

dirpath = './'
path = dirpath + '36331-f40.txt'

# for RRC, this re works fine as there is no OID when a module is declared
module_def = re.compile('^([A-Z][a-zA-Z0-9\-]{0,})(\s{1,}DEFINITIONS\s{1,}[A-Z\-\s]{0,}::=)')

def main():
    
    fd = codecs.open(path, 'r', 'utf-8')
    speclines = fd.readlines()
    fd.close()
    #print(len(speclines))
    
    # every ASN.1 textual definition starts with "-- ASN1START"
    # and ends with "-- ASN1STOP"
    
    inside, start = False, False
    module_name = None
    module = []
    
    for line in speclines:
        if line[:12] == '-- ASN1START':
            if inside:
                raise(Exception('ASN.1 extraction failed: %s' % line))
            inside, start = True, True
            #print('-- ASN1START')
        elif inside and line[:11] == '-- ASN1STOP':
            inside = False
        else:
            if inside:
                #print('inside')
                if start:
                    #print('start')
                    m = module_def.match(line)
                    if m:
                        # new module starting
                        if module and module_name:
                            # write the current one into an .asn file
                            print('%s.asn' % module_name)
                            fd = codecs.open(dirpath + module_name + '.asn', 'w', 'utf-8')
                            fd.write( ''.join(module) )
                            fd.close()
                            module = []
                        module_name = m.group(1)
                        start = False
                        #print(module_name)
                    elif not re.match('^\s{1,}$', line):
                        start = False
                # inside a module: storing the line
                module.append(line)
    #
    # write the last module into an .asn file
    if module and module_name:
        print('%s.asn' % module_name)
        fd = codecs.open(dirpath + module_name + '.asn', 'w', 'utf-8')
        fd.write( ''.join(module) )
        fd.close()
    
    print('> extraction done')
    return 0

if __name__ == '__main__':
    main()

