#!/usr/bin/env python

"""Encapsulation of a set of query args.

Provides a way to store and retrieve query arg names with one value and
methods for parsing and building query arg strings.

Copyright (c) 2009 by Caringo, Inc. -- All rights reserved

This is free software, distributed under the terms of
the New BSD license.

See the LICENSE.txt file included in this archive.
"""

__author__ = "Pat Ray <pat.ray@caringo.com"
__created__ = "3rd October, 2009"
__id__ = "$Id$"

import re
import urllib
QA_PARSER = re.compile("([^=?&]+)=([^&]*)(&)?")

def queryArgsFromString(val):
    """Parse the query args from a string.

    Looks for the starting character '?' and parses out key=value pairs
    from the remainder of the string.
    """
    args = ScspQueryArgs()
    scandx = 0
    while scandx < len(val):
        toks = QA_PARSER.search(val[scandx:])
        start, end = toks.span()
        assert(end > 0) #otherwise, we mad a mistake and there's no progress
        scandx += end
        args.setValue(toks.group(1), toks.group(2))
    return args


class ScspQueryArgs(object):
    """Encapsulates an SCSP query arg string."""
    def __init__(self):
        self._dict = {}

    def setArgs(self, args):
        """Set my dictionary of args.

        @args is a dictionary of {[key,value]...} query args.
        """
        self._dict = args

    def getValue(self, name):
        """Retrieve the value of an arg with name = name."""
        key = self._getMapNameIgnoreCase(name)
        if key:
            return self._dict[key]
        return None

    def containsName(self, name):
        """See if I have an arg named name."""
        return self._getMapNameIgnoreCase(name) != None

    def setValue(self, name, value):
        """Set the value of an arg."""
        key = self._getMapNameIgnoreCase(name)
        if key:
            del self._dict[key]
        self._dict[name] = (value or 'yes') # Note that this may change the case of the key; if no value is given then default to "yes"

    def addAll(self, args):
        """Copy all of the args from args into me.

        This will replace any existing args that have a name that matches an
        input arg name but will otherwise leave the stored args untouched.

        @args is either an ScspQueryArgs instance or dictionary of
        (key,value) pairs.

        """
        if type(args) == ScspQueryArgs:
            argDict = args.getArgList()
        else:
            argDict = args or {}

        for name, value in argDict.iteritems():
            key = self._getMapNameIgnoreCase(name)
            if key:
                del self._dict[key]
            self._dict[name] = (value or 'yes')

    def remove(self, name):
        """Remove a query arg with name = name if I'm storing one."""
        key = self._getMapNameIgnoreCase(name)
        if key:
            del self._dict[key]

    def getArgList(self):
        """Return the dictionary of stored query args."""
        return self._dict

    def toQueryArgString(self):
        """Construct a string suitable for passing to HTTP."""
        return urllib.urlencode(self._dict)

    def _getMapNameIgnoreCase(self, name):
        """Return the case-insensitive key name for name."""
        lowername = name.lower()
        for key in self._dict.keys():
            if key is not None and key.lower() == lowername:
                return key
        return None

    def __str__(self):
        return self.toQueryArgString()

    def __eq__(self, other):
        return str(self) == str(other)
