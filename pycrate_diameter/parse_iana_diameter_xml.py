# -*- coding: UTF-8 -*-
#/*
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2019. Benoit Michau. P1Sec.
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
# * File Name : pycrate_diameter/parse_iana_diameter_xml.py
# * Created : 2019-07-30
# * Authors : Benoit Michau 
# *--------------------------------------------------------
# */


import os
import sys
import re
import time
import pprint
from lxml import etree


# those are the xml files taken from the IANA web pages
# https://www.iana.org/assignments/aaa-parameters/aaa-parameters.xml
FILENAME_aaa_parameters = os.path.dirname(__file__) + '/aaa-parameters.xml'
# https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
FILENAME_address_family_numbers = os.path.dirname(__file__) + '/address-family-numbers.xml'
# https://www.iana.org/assignments/radius-types/radius-types.xml
FILENAME_radius_types = os.path.dirname(__file__) + '/radius-types.xml'
#
# and this is a Python file with xml converted to dict
FILENAME_python_dicts = os.path.dirname(__file__) + '/iana_diameter_dicts.py'


'''
xml file structure for aaa-parameters.xml

AVP Codes:
    AVP Code -> Attribute Name
AVP Specific Values:
    Attribute Name, AVP Code:
        AVP Value -> Value Name
    ...
AVP Flags Value
    Bit -> Name
Application ID
    ID Value -> Name
Command Codes
    Code Value -> Name


xml file structure for address-family-numbers.xml

Address Family Numbers:
    Number -> Description
'''


# some regexp
RE_INT      = re.compile(r'^[1-9]{1}[0-9]{0,}$')
RE_HEX      = re.compile(r'0x[0-9]{2,4,6,8,10,12,14,16}')
RE_SV_CODE  = re.compile(r'\(code (%s)\)' % RE_INT.pattern[1:-1])


def build_dict_from_xml(filename=FILENAME_aaa_parameters):
    if filename == FILENAME_aaa_parameters:
        T = etree.parse(filename).getroot()
        for child in T.getchildren():
            subchild_list = child.getchildren()
            if not subchild_list:
                pass
            elif subchild_list[0].text == 'AVP Codes':
                dict_avp_codes = build_dict_from_val_name(
                    [i for i in subchild_list if i.tag == '{http://www.iana.org/assignments}record'])
            elif subchild_list[0].text == 'AVP Specific Values':
                dict_avp_spec_val = build_dict_from_avp_spec_val(
                    [i for i in subchild_list if i.tag == '{http://www.iana.org/assignments}registry'])
            elif subchild_list[0].text == 'Application IDs':
                dict_app_id = build_dict_from_val_name(
                    [i for i in subchild_list if i.tag == '{http://www.iana.org/assignments}record'])
            elif subchild_list[0].text == 'Command Codes':
                dict_cmd_codes = build_dict_from_val_name(
                    [i for i in subchild_list if i.tag == '{http://www.iana.org/assignments}record'])
        #
        return (dict_app_id,
                dict_cmd_codes,
                dict_avp_codes,
                dict_avp_spec_val)
    #
    elif filename == FILENAME_address_family_numbers:
        T = etree.parse(filename).getroot()
        for child in T.getchildren():
            subchild_list = child.getchildren()
            if not subchild_list:
                pass
            elif subchild_list[0].text == 'Address Family Numbers':
                dict_addr_fam_nums = build_dict_from_val_name(
                    [i for i in subchild_list if i.tag == '{http://www.iana.org/assignments}record'])
        #
        return dict_addr_fam_nums
    #
    elif filename == FILENAME_radius_types:
        T = etree.parse(filename).getroot()
        for child in T.getchildren():
            subchild_list = child.getchildren()
            if not subchild_list:
                pass
            elif subchild_list[0].text == 'RADIUS Attribute Types':
                dict_radius_avp_codes = build_dict_from_val_name(
                    [i for i in subchild_list if i.tag == '{http://www.iana.org/assignments}record'])
        #
        return dict_radius_avp_codes
    #
    else:
        print('error: invalid filename')


def build_dict_from_val_name(recordlist):
    d = {}
    for rec in recordlist:
        code, name = rec.getchildren()[:2]
        m = RE_INT.match(code.text)
        if m:
            d[int(m.group())] = re.sub('\s{1,}', ' ', name.text)
    return d


def build_dict_from_avp_spec_val(registrylist):
    d = {}
    for reg in registrylist:
        childlist = reg.getchildren()
        m = RE_SV_CODE.search(childlist[0].text)
        if m:
            code = int(m.group(1))
            if code not in d:
                d[code] = {}
            subd = d[code]
            for rec in [i for i in childlist if i.tag == '{http://www.iana.org/assignments}record']:
                val, name = rec.getchildren()[:2]
                m = RE_INT.match(val.text)
                if m:
                    subd[int(m.group())] = re.sub('\s{1,}', ' ', name.text)
                # can also have flag values, e.g. 0x0000000000000020
                else:
                    m = RE_HEX.match(val.text)
                    if m:
                        subd[int(m.group(), 16)] = re.sub('\s{1,}', ' ', name.text)
    return d


# generated file header
_Header =    '''# -*- coding: UTF-8 -*-
#/*
# * Software Name : pycrate
# * Version : 0.4
# *
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
# * File Name : pycrate_diameter/iana_diameter_dicts.py
# * Created : %s
# * Authors : Benoit Michau
# *--------------------------------------------------------
# */
''' % time.strftime('%Y-%m-%d')


def gen_python_dict():
    #
    AVPRadCodes_dict = build_dict_from_xml(FILENAME_radius_types)
    AppID_dict, Cmd_dict, AVPDiamCodes_dict, AVPSpecVal_dict = build_dict_from_xml(FILENAME_aaa_parameters)
    AddrFamNums_dict = build_dict_from_xml(FILENAME_address_family_numbers)
    AVPCodes_dict = dict(AVPRadCodes_dict)
    AVPCodes_dict.update(AVPDiamCodes_dict)
    #
    # serialize those dicts into a new Python file
    if os.path.exists(FILENAME_python_dicts):
        print('WARN: %s already exists, please move it first' % FILENAME_python_dicts)
        return 0
    #
    with open(FILENAME_python_dicts, 'w') as fd:
        fd.write(_Header)
        fd.write('\n')
        #
        # set a pretty formatter for the dicts
        pf = pprint.PrettyPrinter(indent=2, sort_dicts=True)
        fd.write('AVPRadCodes_dict  = \\\n%s\n\n' % pf.pformat(AVPRadCodes_dict))
        fd.write('AppID_dict        = \\\n%s\n\n' % pf.pformat(AppID_dict))
        fd.write('Cmd_dict          = \\\n%s\n\n' % pf.pformat(Cmd_dict))
        fd.write('AVPDiamCodes_dict = \\\n%s\n\n' % pf.pformat(AVPDiamCodes_dict))
        fd.write('AVPSpecVal_dict   = \\\n%s\n\n' % pf.pformat(AVPSpecVal_dict))
        fd.write('AddrFamNums_dict  = \\\n%s\n\n' % pf.pformat(AddrFamNums_dict))
        fd.write('AVPCodes_dict     = \\\n%s\n\n' % pf.pformat(AVPCodes_dict))
        #
        print('file generated: %s' % FILENAME_python_dicts)
    #
    return 0


if __name__ == '__main__':
    sys.exit(gen_python_dict())
    
