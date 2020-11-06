#!/usr/bin/env python

"""Provide a first-class date object for use with CAStor Lifepoints.

Dates are represented either as an explicit date or as an offset in seconds
from the time the SCSPDate object was created.  These can then be converted
to a string in the form that is used by a lifepoint.

An example of a formatted date string is as follows:
    Fri, 12 Dec 2005 15:59:02 GMT

See meta.py for details on lifepoints and their formats.

IMPORTANT DEVELOPER NOTE: DO NOT INCLUDE OR IMPORT ANY PROPRIETARY CODE.
This module is distributed in source form along with sample client code.

Copyright (c) 2006-2010 by Caringo, Inc. -- All rights reserved

This is free software, distributed under the terms of
the New BSD license.

See the LICENSE.txt file included in this archive.
"""

__author__ = 'Brian Guetzlaff <brian.guetzlaff@caringo.com>'
__created__ = '22 October 2010'
__id__ = "$Id: meta.py 27515 2010-09-22 14:25:02Z dyoakley $"

import time, calendar

DATE_FORMAT = '%a, %d %b %Y %H:%M:%S GMT'

class SCSPDate (object):
    """
    SCSPDate is used to hold a timestamp for Lifepoint purposes.
    """
    def __init__(self, date=None, offset=None):
        """
        SCSPDate should be created with either an explicit date (in GMT/UTC) or an offset (in seconds) from the
        the time when the SCSPDate is created.  If both or neither is provided, then ValueError is raised.  An
        Aoffset of 0 indicates an SCSPDate set to now (GMT)
        """
        if not date and (None == offset):
            raise ValueError('Either a date or an offset (in seconds) must be provided')
        if date and offset:
            raise ValueError('Only one of a date or an offset (in seconds) may be provided')

        if date:
            if isinstance(date, time.struct_time):
                self._date = date
            elif isinstance(date, SCSPDate):
                self._date = date._date
            else:
                self._date = time.gmtime(date)
        else:
            self._date = time.gmtime(time.time() + offset)

    def sinceEpoch(self):
        return calendar.timegm(self._date)

    @staticmethod
    def fromString(dateString):
        return SCSPDate(date=time.strptime(dateString, DATE_FORMAT))

    def __str__(self):
        return time.strftime(DATE_FORMAT, self._date)
