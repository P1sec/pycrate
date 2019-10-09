# -*- coding: UTF-8 -*-
#/**
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
#*/

__all__ = [
    'FILENAME_aaa_parameters',
    'FILENAME_address_family_numbers',
    'FILENAME_radius_types',
    'build_dict_from_xml'
    ]


import os
import re
from lxml import etree


FILENAME_aaa_parameters = os.path.dirname(__file__) + '/aaa-parameters.xml'
FILENAME_address_family_numbers = os.path.dirname(__file__) + '/address-family-numbers.xml'
FILENAME_radius_types = os.path.dirname(__file__) + '/radius-types.xml'


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
RE_SV_CODE  = re.compile(r'\(code (%s)\)' % RE_INT.pattern)


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
            d[int(m.group())] = name.text
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
                    subd[int(m.group())] = name.text
                # can also have flag values, e.g. 0x0000000000000020
                else:
                    m = RE_HEX.match(val.text)
                    if m:
                        subd[int(m.group(), 16)] = name.text
    return d


