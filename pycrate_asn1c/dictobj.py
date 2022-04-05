# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2016. Benoit Michau. ANSSI.
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
# * File Name : pycrate_asn1c/dictobj.py
# * Created : 2016-03-02
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from .utils import python_version

#------------------------------------------------------------------------------#
# ordered dictionnary
#------------------------------------------------------------------------------#
# It provides the same API as a Python dict object

class ASN1Dict(object):
    '''
    Custom and simple OrderedDict class, pickelable.
    
    Uses _dict attribute to store the dict object
    and _index attribute to store the ordered list of dict indexes.
    '''
    
    # pickling methods
    def __getstate__(self):
        return (self._index, self._dict)
    
    def __setstate__(self, state):
        self._index = state[0]
        self._dict = state[1]
    
    # standard dict methods
    def __init__(self, items=[]):
        self._dict = {}
        self._index = []
        for k, v in items:
            self.__setitem__(k, v)
    
    def __repr__(self):
        if not self._dict:
            return '{}'
        else:
            return '{\n%s\n}' % ',\n'.join(['%s: %s' % (k, repr(self[k]).replace('\n', '\n '))
                                            for k in self])
    
    def __len__(self):
        return len(self._index)
    
    def __getitem__(self, key):
        return self._dict[key]
    
    def __setitem__(self, key, val):
        self._dict[key] = val
        if key not in self._index:
            self._index.append(key)
    
    def __delitem__(self, key):
        del self._dict[key]
        self._index.remove(key)
    
    def __iter__(self):
        return self._index.__iter__()
    
    def __contains__(self, item):
        return self._dict.__contains__(item)
    
    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self._index == other._index and self._dict == other._dict
        else:
            return False
    
    def __ne__(self, other):
        if isinstance(other, self.__class__):
            return self._index != other._index or self._dict != other._dict
        else:
            return False
    
    def index(self, key):
        return self._index.index(key)
    
    def clear(self):
        self._dict.clear()
        del self._index[:]
    
    def update(self, other):
        for key, val in other.items():
            self.__setitem__(key, val)
    
    if python_version <= 2:
        def keys(self):
            return list(self._index)
        
        def items(self):
            return [(k, self._dict[k]) for k in self._index]
        
        def values(self):
            return [self._dict[k] for k in self._index]
    
    else:
        def keys(self):
            return self._index.__iter__()
        
        def items(self):
            # TODO: create a true iterator instead of a complete list over which we then iterate
            return [(k, self._dict[k]) for k in self._index].__iter__()
        
        def values(self):
            # TODO: create a true iterator instead of a complete list over which we then iterate
            return [self._dict[k] for k in self._index].__iter__()
    
    # custom pycrate_asn1 methods
    def copy(self):
        """
        returns an equal but independent copy of self
        """
        copy = self.__class__()
        copy._dict.update(self._dict)
        copy._index.extend(self._index)
        return copy

