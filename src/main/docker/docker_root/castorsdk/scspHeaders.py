#!/usr/bin/env python

"""Encapsulation of a set of HTTP query or response headers.

Provides a way to  store and retrieve header names with one or more
values and methods for parsing and building header strings.

Note that headers are stored and retrieved case-insensitive.

Other helper classes include ScspAuthentication and ScspAuthorization.
See docstrings on those classes for more details.

Copyright (c) 2010 by Caringo, Inc. -- All rights reserved

This is free software, distributed under the terms of
the New BSD license.

See the LICENSE.txt file included in this archive.
"""

__author__ = "Pat Ray <pat.ray@caringo.com"
__created__ = "3rd October, 2009"
__id__ = "$Id$"

import meta
import time, calendar
import re
import scspQueryArgs
from scspDate import SCSPDate, DATE_FORMAT
from client import pathEscape

CLUSTER_ADMIN_REALM = 'CAStor administrator'

REPS_COUNT_PREFIX = "reps"
DELETION_CONSTRAINT_PREFIX = "delet"
COMPRESSION_CONSTRAINT_PREFIX = "compress"

EC_REPS_DELIM = ':'

REPS_COUNT_ATTRIBUTE = (REPS_COUNT_PREFIX, "reps count")
DELETION_CONSTRAINT_ATTRIBUTE = (DELETION_CONSTRAINT_PREFIX, "deletion constraint")
LIFEPOINT_ATTRIBUTES = {
#   four-char key : (prefix, description)
    "reps" : REPS_COUNT_ATTRIBUTE,
    "dele" : DELETION_CONSTRAINT_ATTRIBUTE }

LP_PARSER = re.compile("""
                            # VERBOSE enables this commented syntax
    [ ]*                    # allow spaces before string
    \[[ ]*                      # parse out the date; starts with a [
    (?P<date>
        [^\]]*              # date string is everything up to the closing ]
    )
    [ ]*\][ ]*                  # ends with a ]
    ([a-zA-Z]+[^, ]*        # parse first lifepoint attribute
    )                       # the value may be missing
    [ ]*,?[ ]*              # get rid of whitespace
    ([a-zA-Z]+[^, ]*        # parse additional lifepoint attribute (if any)
    )?                      # the value may be missing
    [ ]*,?[ ]*              # get rid of whitespace
    ([a-zA-Z]+[^, ]*        # parse additional lifepoint attribute (if any)
    )?                      # the value may be missing
    [ ]*,?[ ]*              # get rid of whitespace
                            # note that this is not quite right since the lp must have at least one rep or constraint,
                            # but we'll handle that in the parsing routine
""", re.VERBOSE)

""" Convenience methods, constants, and variables for various args and headers """

""" Integrity Seals """
""" Hash types """
hashAlgorithms = ['md5', 'sha1', 'sha256', 'sha384', 'sha512']
HA_MD5 = 0
HA_SHA1 = 1
HA_SHA256 = 2
HA_SHA384 = 3
HA_SHA512 = 4


def integritySealFromHeaders(headers):
    """ Pulls a hash type and hash value from a Location header.

    @return a [hashType value, hash value] or None if no seal is found.
    """
    val = headers.get('Location', None)
    if val is None:
        return None
    else:
        qa = scspQueryArgs.queryArgsFromString(val)
        if qa.containsName('hashtype') and qa.containsName('hash'):
            return [qa.getValue('hashtype'), qa.getValue('hash')]
        else:
            return None

def secondsFromDateString(sdate):
    """Retrieves a count of seconds since the epoch from a date string.

    @sdate is a date string in standard format.
    """
    return calendar.timegm(time.strptime(sdate, DATE_FORMAT))

def dateStringFromSeconds(seconds):
    """Turns a count of seconds since the epoch into a date string.

    @seconds is a count of seconds since the epoch.
    @returns a date string in standard format
    """
    return time.strftime(DATE_FORMAT, time.gmtime(seconds))


def lifepointFromString(value, allowExtraData=False):
    """Parse a lifepoint from a header value string.

    The value must be a single-valued header value.
    May raise AttributeError or ValueError from parse
    @value is a lifepoint header value
    @return a ScspLifepoint instance
    """
    tokens = LP_PARSER.search(value)

    if tokens is None:
        raise AttributeError('Invalid Lifepoint string: %s' % value)

    start, end = tokens.span()
    sdate = tokens.group("date")
    groups = (tokens.groups())[1:]
    attrDict = {}
    customAttributes = []

    for group in groups:
        if group is None:
            break

        key = group[:4]
        attr = LIFEPOINT_ATTRIBUTES.get(key)

        if attr is None:
            # We've got a custom lifepoint attribute on our hands
            customAttributes.append(group)
            continue

        prefix = attr[0]

        if group.find(prefix) == 0:
            if prefix in attrDict:
                description = attr[1]
                raise ValueError('More than one %s specified for Lifepoint' % description)

            attrDict[prefix] = group

    constraint = attrDict.get(DELETION_CONSTRAINT_PREFIX)
    reps = attrDict.get(REPS_COUNT_PREFIX)

    if reps is not None:
        repsParts = reps[len(REPS_COUNT_PREFIX)+1:].split(EC_REPS_DELIM)

        if 1 == len(repsParts):
            reps = int(repsParts[0])
        elif 2 == len(repsParts):
            reps = tuple(map(int, repsParts))
        else:
            raise ValueError('Invalid reps constraint specified for Lifepoint')

    if (not allowExtraData) and (end != len(value)):
        raise ValueError('Invalid trailing string on Lifepoint')

    if (constraint is None) and (reps is None) and (not customAttributes):
        raise ValueError('Lifepoint must have one or more constraints (deletion, reps, or custom)')

    date = None

    if len(sdate) > 0:
        date = secondsFromDateString(sdate)

    return ScspLifepoint(end=date, constraint=constraint, reps=reps, custom=customAttributes)

def lifepointsFromString(value):
    """Parse one or more lifepoints from a header value string.

    The value may be a multi-valued header value.
    May raise AttributeError or ValueError from parse.
    @value is a lifepoint header value
    @return a list of ScspLifepoint instances
    """
    lps = []
    scanned = 0
    while scanned < len(value):
        while (scanned < len(value)) and (value[scanned] in [' ', '\t']):
            scanned += 1

        if scanned >= len(value):
            break

        offset = scanned
        scanned += LP_PARSER.search(value[offset:]).span()[1]
        lp = lifepointFromString(value[offset:], allowExtraData=True)
        lps.append(lp)

        #see if there's another one
        while (scanned < len(value)) and (value[scanned] in [' ', '\t']):
            scanned += 1

        if (scanned < len(value)) and (value[scanned] == ','):
            scanned += 1
    return lps

def policyFromHeaders(headers):
    """Parse a list of lifepoints from headers.

    May raise AttributeError or ValueError from parse.
    @value is a ScspHeader object
    @return a list of ScspLifepoint instances
    """
    policy = []
    if headers:
        vals = headers.getHeaderValues('Lifepoint')
        if vals:
            for v in vals:
                policy.extend(lifepointsFromString(v))
    return policy

def authenticationFromHeaders(headers):
    """Parse an auth challenge from Scsp Headers.

    @headers is an ScspHeaders instance, normally a response from an
        ScspCommand execution.
    @return an ScspAuthentication containing the challenge.
    """
    auth = ScspAuthentication()
    params = headers.getDigestAuthChallenge()
    auth.realm = params['realm']
    auth.nonce = params['nonce']
    auth.opaque = params.get('opaque','')
    auth.stale = params.get('stale','false').lower() == 'true'
    auth.qop = params.get('qop','')
    auth.challengeParams = params
    assert(params['algorithm'] == 'MD5')
    return auth

class ScspLifepoint(object):
    """Encapsulation of an SCSP Lifepoint header value"""
    def __init__(self, end=None, seconds=0, minutes=0, hours=0, days=0,
                 constraint=None, reps=None, custom=[]):
        """@end seconds since the epoch
        @constraint string "delete" or "deletable=yes|no"
        @reps integer count of reps, or tuple (data, parity) Erasure Coding specification
        @custom list of custom attribute strings
        @seconds, minutes, hours, days is the representation of time from now

        Either end must be None or all of seconds, minutes, hours, and days
        must be None.
        """

        if seconds or minutes or hours or days:
            assert(end is None)
            end = int(time.time())
            end += seconds
            end += minutes * 60
            end += hours * 60 * 60
            end += days * 24 * 60 * 60

        if not (end is None):
            self.end = SCSPDate(date=time.gmtime(end))
        else:
            self.end = None

        self.constraint = constraint
        self.reps = reps
        self.custom = []
        self.custom.extend(custom)    # help assure we're at least dealing with an iterable
        self._checkvalues()

    def makeConstraints(self):
        """Build constraints from constraint and reps and custom."""
        constraints = ''

        if (self.constraint is not None) and (len(self.constraint) > 0):
            constraints = self.constraint

        if self.reps is not None:
            if len(constraints) > 0:
                constraints += ', '

            if isinstance(self.reps, int):
                reps = self.reps  # default string conversion is okay
            else:
                reps = EC_REPS_DELIM.join(map(str, self.reps[:2]))

            constraints += 'reps=%s' % reps

        if self.custom and (0 < len(self.custom)):
            if len(constraints) > 0:
                constraints += ', '

            constraints += ', '.join(self.custom)

        return constraints

    def _checkvalues(self):
        if (not self.constraint is None) and not (self.constraint in ['delete', 'deletable=no', 'deletable=yes', 'deletable=false', 'deletable=true']):
            raise ValueError('Invalid delete constraint')

        if (self.reps is not None):
            if isinstance(self.reps, int):
                if self.reps <= 0:
                    raise ValueError('Invalid reps (cannot be negative)')
            else:
                for part in self.reps:
                    if part <= 0:
                        raise ValueError('Invalid reps (no part may be negative)')

        for attr in self.custom:
            if ',' in attr:
                raise ValueError('Invalid custom attribute: [%s]' % attr)

    def __str__(self):
        if not (self.end is None):
            endStr = str(self.end)
        else:
            endStr = ''
        return '[%s] %s' % (endStr, self.makeConstraints())

    def addCustomAttribute(self, attribute):
        self.custom.append(attribute)

class ScspAuthentication(object):
    """Holds a challenge and response.

    Will be filled with the challenge parameters on a 401 response. The client
    can add user, password, nonce, and nonce count and pass in the whole shebang
    to an ScspHeaders instance to set up authentication for a command.

    The client only needs to supply the user name, realm, and password in a new
    ScspAuthentication object if it's not trying to preemptively authenticate.
    If it is retrying on the same resource with a fresh (that is, non-stale) nonce,
    it can parse the ScspAuthentication object from a response, fill in the user
    name and password, and pass the object back into a new request for the same
    resource.
    """

    def __init__(self):
        self.user = ''
        self.password = ''
        self.cnonce = ''
        self.noncecount = -1
        self.realm = ''
        self.nonce = ''
        self.opaque = ''
        self.stale = ''
        self.qop = ''
        self.algorithm = 'MD5' # we don't understand anything else
        self.uri = '' #convenient placeholder
        self.challengeParams = {}

class ScspAuthorization(object):
    """
    Properly formats an SCSP authorization header

    To retrieve a list of validation or parsing errors, check the 'errors' member,
    which will contain a list of errors.  This class can be used to format an SCSP
    authorization header entry to be added to an ScspHeaders object, or can also
    parse authorization information from a response header.

    It is recommended that the client calls validate() on an ScspAuthorization object
    to reduce potential ambiguity due to duplicate or invalid authorization entries.
    """

    # Values for Authorization
    AUTHORIZATION_HEADER_NAME = 'Castor-Authorization'

    # Generic operations that may have authorization applied to them
    ALL_OP = ''
    VIEW_OP = 'view'
    CHANGE_OP = 'change'

    # Specific operations that may have authorization applied to them.  These supercede the generic operations
    PUT_OP = 'put'
    COPY_OP = 'copy'
    APPEND_OP = 'append'
    GET_OP = 'get'
    HEAD_OP = 'head'
    DELETE_OP = 'delete'
    POST_OP = 'post'

    # Convenience realms
    ANY_REALM = ''

    def __init__(self):
        self._ops = {}
        self.errors = []

    def addAuthorization(self, operation, realm):
        if None == operation:
            operation = ScspAuthorization.ALL_OP

        op = operation.lower()

        if None == realm:
            realm = ScspAuthorization.ANY_REALM

        if (ScspAuthorization.ALL_OP == op) and (ScspAuthorization.ANY_REALM == realm):
            raise ValueError('Empty rules are not allowed; either a specific operation or a specific realm must be provided')

        if op not in self._ops:
            self._ops[op] = []

        if isinstance(realm, list):     # allows x.addAuthorization(op1, y.getAuthorization(op2))
            if 0 == len(realm):
                raise ValueError('At least one realm must be provided')
            self._ops[op].extend(realm)
        else:
            self._ops[op].append(realm)

    def resetAuthorization(self, operation):
        op = operation.lower()
        if op in self._ops:
            del self._ops[op]

    def hasAuthorization(self, operation):
        return operation.lower() in self._ops

    def getAuthorization(self, operation):
        """Returns a list of realms authorized for the given operation"""
        return self._ops[operation.lower()]

    def __str__(self):
        """Returns the full SCSP authorization header"""
        return ScspAuthorization.AUTHORIZATION_HEADER_NAME + ': ' + self.getAuthSpec()

    def resetErrors(self):
        self.errors = []

    def getAuthSpec(self):
        """Returns ONLY the authorization specification portion of the full SCSP authorization header"""
        dontEscape = ''.join([' ', ':', ','])   # written this way for better clarity

        def _formatAuthSpec(op, realm):
            if op == ScspAuthorization.ALL_OP:
                return realm
            return op + '=' + realm

        return ', '.join([_formatAuthSpec(op, pathEscape(realm, dontEscape)) for op, realms in self._ops.iteritems() for realm in realms])

    @staticmethod
    def _parseInto(header, authObj):
        ops = authObj._ops
        parseErrors = authObj.errors

        try:
            # If we were given the full header, lop off the header name and ':'
            if header[:len(ScspAuthorization.AUTHORIZATION_HEADER_NAME)] == ScspAuthorization.AUTHORIZATION_HEADER_NAME:
                header = header[len(ScspAuthorization.AUTHORIZATION_HEADER_NAME) + 1:]

            for spec in [authSpec.strip() for authSpec in header.split(',')]:
                if '=' in spec:
                    op, realm = spec.split('=')
                else:
                    op = ScspAuthorization.ALL_OP
                    realm = spec

                op = op.strip().lower()
                realm = realm.strip()

                if (ScspAuthorization.ALL_OP == op) and (ScspAuthorization.ANY_REALM == realm):
                    parseErrors.append('Empty authorization specification (",=,") found when parsing header (%s)' % header)

                if op in ops:
                    ops[op].append(realm)
                    parseErrors.append('Duplicate realm ("%s") defined for operation ("%s"); authorization behavior will be ambiguous' % (realm, op))
                else:
                    ops[op] = [realm]
        except Exception as ex:
            parseErrors.append('Error while parsing authorization header string (%s): %s' % (header, ex))

    @staticmethod
    def fromHeaders(headers):
        """
        If the Castor-Authorization header is present in the given headers, this will create a corresponding
        ScspAuthorization object.

        It is recommended that you check the 'errors' member of the returned ScspAuthorization object for
        any parsing errors, as these can be indicative of ambiguous authorization rules.  It is also highly
        recommended that you call validate() on the returned object, as validate() is able to catch more
        errors.
        """
        if not headers.containsName(ScspAuthorization.AUTHORIZATION_HEADER_NAME):
            return ScspAuthorization()

        result = ScspAuthorization()

        for header in headers.getHeaderValues(ScspAuthorization.AUTHORIZATION_HEADER_NAME):
            ScspAuthorization._parseInto(header, result)

        return result

    @staticmethod
    def fromString(header):
        """
        Parses the given Castor-Authorization header into an ScspAuthorization object

        It is recommended that you check the 'errors' member of the returned ScspAuthorization object for
        any parsing errors, as these can be indicative of ambiguous authorization rules.  It is also highly
        recommended that you call validate() on the returned object, as validate() is able to catch more
        errors.
        """
        result = ScspAuthorization()
        ScspAuthorization._parseInto(header, result)
        return result

    def validate(self):
        """
        Ensures that the operations and realms within this object are of a valid format.

        @return True if validation was successful, False otherwise.  If False is returned, it is recommended that you
            check the 'errors' member of the ScspAuthorization object for validation errors.
        """
        validOps = [ScspAuthorization.ALL_OP, ScspAuthorization.VIEW_OP, ScspAuthorization.CHANGE_OP, ScspAuthorization.PUT_OP,
                    ScspAuthorization.COPY_OP, ScspAuthorization.APPEND_OP, ScspAuthorization.GET_OP, ScspAuthorization.HEAD_OP,
                    ScspAuthorization.DELETE_OP, ScspAuthorization.POST_OP]
        illegalRealmChars = ':,'

        self.resetErrors()

        try:
            for op, realms in self._ops.iteritems():
                if op not in validOps:
                    self.errors.append('Unsupported operation ("%s") for authorization' % op)

                if 1 < len(realms):
                    self.errors.append('Multiple realms ("%s") defined for operation ("%s"); authorization behavior will be ambiguous' % (str(realms), op))

                if 1 > len(realms):
                    # Shouldn't happen, but for completeness...
                    self.errors.append('Missing realm for operation ("%s"); authorization behavior will be ambiguous' % op)

                for realm in realms:
                    if (op == ScspAuthorization.ALL_OP) and (realm == ScspAuthorization.ANY_REALM):
                        self.errors.append('Empty authorization specification (ScspAuthorization.ALL_OP=ScspAuthorization.ANY_REALM, or "=") found');

                    for c in illegalRealmChars:
                        if c in realm:
                            self.errors.append('Illegal character ("%s") found in realm ("%s") for operation ("%s")' % (c, realm, op))
        except Exception as ex:
            self.errors.append('Error while validating ScspAuthorization object: %s' % ex)

        return 0 == len(self.errors)

class ScspHeaders(object):
    """Encapsulates headers for a request or a response"""
    def __init__(self):
        self.authentication = None
        self.headers = meta.MetaDataDictionary()

    def __str__(self):
        return str(self.headers)

    def setHeaders(self, dict):
        """Add all of the headers from the input dictionary into me.

        @dict is a dictionary of {key:[value, value...],...}
        """
        for item in dict.items():
            for v in item[1]:
                self.headers[item[0]] = v

    def getHeaderValues(self, name):
        """Get all of the header values for a particular header name.

        @name is the header name.
        @return the list of header values.
        """
        return self.headers.getAll(name)

    def get(self,name, default=None):
        """Get the first header value for a particular header name.

        Note that this is primarily a convenience function where there is only
        one value for a header.

        @name is the header name.
        @default is the value to return we don't store this header name
        @return a header valued stored for name or default if we don't
            have one.
        """
        return self.headers.get(name, default)

    def containsName(self, name):
        """See if I store a header with name = name.

        @name is the header name to look for.
        @result is True if I store a header with name = name.
        """
        return name in self.headers

    def getNamesWithPrefix(self, prefix):
        """Retrieve a list of header names that have prefix as a prefix, case-insensitive.

        @prefix is the prefix to test for.
        @return the list of header names stored by me that start with prefix.
        """
        lowerprefix = prefix.lower()
        return [k for k in self.headers.keys() if k.lower().startswith(lowerprefix)]

    def addValue(self, name, value):
        """Set a header value.

        @name is the name of the header to set.
        @value is the string value to set.
        """
        self.headers[name] = value

    def replaceValue(self, name, value):
        """Replace a header value.

        @name is the name of the header to replace.
        @value is the string value to set.
        """
        self.remove(name)
        self.headers[name] = value

    def addAll(self, other):
        """Copy all of the header values from other into me.

        This will preserve existing header values.

        @other is an ScspHeaders instance to copy from.
        """
        self.headers.combine(other.headers)

    def remove(self, name):
        """Remove all traces of the header with name = name.

        @name is the the header name to remove.
        """
        del self.headers[name]

    def removeAll(self):
        """Empty me of all headers."""
        for k in self.headers.keys():
            del self.headers[k]

    def toHeaderList(self):
        """Return my headers as a [(name,value)] list.

        This operation can result in a list that contains multiple entries
        with the same name field.

        @return a list of (name,value) pairs representing my headers.
        """
        result = []
        for k in self.headers.keys():
            result = result + [(k,v) for v in self.headers.getAll(k)]
        return result

    def addRange(self, start, end):
        """Add a range header.

        @start is the start of range. If value is < 0, then start string
            value for the range will be empty.
        @end is the end of range. If value < 0, then end string value
            for the range will be empty.
        """
        sStart = str(start)
        sEnd = str(end)
        if start < 0:
            sStart = ''
        if end < 0:
            sEnd = ''
        self.addValue('Range', 'bytes=' + sStart + '-' + sEnd)

    def addLifepoint(self, date=None, deleteConstraint=None, reps=None):
        """Add a lifepoint header."""
        lp = ScspLifepoint(end=date, constraint=deleteConstraint, reps=reps)
        self.headers.addLifepoint(end=date, constraints=lp.makeConstraints())

    def nameCount(self):
        """Retrieve the count of unique header names that I store."""
        return len(self.headers.keys())

    def headerCount(self):
        """Retrieve the count of unique header values that I store."""
        return len(self.toHeaderList())

    def containsValue(self, name, value):
        """See if I store value for a header with name = value."""
        return self.headers.hasHeaderValue(name, value)

    def __eq__(self, other):
        return self.headers == other.headers and self.authentication == other.authentication
