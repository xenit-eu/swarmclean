#!/usr/bin/env python

"""Manage information about the streams being stored by the CAStor cluster.

Externally, in the protocols and disk image, metadata is represented
as HTTP-style headers prepended to the stream data.  Headers are
line-oriented text, each one terminated by a newline with the entire
meta data section being terminated by an empty line, after which
binary stream data starts.

An example of metadata prepended to a stream is:

    Date: Mon, 30 May 2005 15:59:02 GMT\n
    Last-Modified: Tue, 27 Apr 2004 20:14:55 GMT\n
    Server: CAStor Cluster/v1b1\n
    Connection: close\n
    Content-Length: 43402\n
    Content-Type: image/jpeg\n
    Lifepoint: [Fri, 12 Dec 2005 15:59:02 GMT] reps=3\n
    Lifepoint: [Wed, 08 Jun 2005 15:59:02 GMT] reps=0\n
    Lifepoint: [Tue, 09 Jun 2005 15:59:02 GMT] delete\n
    \n
    [ content-stream ]

Internally, metadata is represented as a dictionary, where the keys
are the header names (e.g., 'Date' in the first header line above) and
the value is an array of strings, representing the (perhaps multiple)
values supplied on the header lines. The above example is equivalent
to the following metadata dictionary:

    {'Date': ['Mon, 30 May 2005 15:59:02 GMT']
    'Last-Modified': ['Tue, 27 Apr 2004 20:14:55 GMT']
    'Server': ['CAStor Cluster/v1b1']
    'Connection': ['close']
    'Content-Length': ['43402']
    'Content-Type': ['image/jpeg']
    'Lifepoint': ['[Fri, 12 Dec 2005 15:59:02 GMT] reps=3'
                  '[Wed, 08 Jun 2005 15:59:02 GMT] reps=0'
                  '[[Tue, 09 Jun 2005 15:59:02 GMT] delete']}

The original order of the header values is maintained in the value array for that header.

IMPORTANT DEVELOPER NOTE: DO NOT INCLUDE OR IMPORT ANY PROPRIETARY CODE.
This module is distributed in source form along with sample client code.

Copyright (c) 2006-2010 by Caringo, Inc. -- All rights reserved

This is free software, distributed under the terms of
the New BSD license.

See the LICENSE.txt file included in this archive.
"""

__author__ = "Jim Dutton <jim.dutton@caringo.com>"
__created__ = "25 July 2005"
__id__ = "$Id$"

import time, mimetypes, base64, re, copy, string, io
import cgi  # only for parse_qs() which will be in urlparse in python 2.6
from urllib.parse import urlparse
try:
    import hashlib
    MD5 = hashlib.md5
except ImportError:
    import md5
    MD5 = md5.new
from inspect import isfunction

# Regular expression for parsing stored metadata, which has
# no irregularities.
METADATA_LINE_PARSER = re.compile("""
                            # VERBOSE enables this commented syntax
    ^                       # Must be at the start of the line
    (?P<name> [^:]*)        # Everything before the colon is the name
    :[ ]                    # the :<space> separator
    (?P<value> (?:.*))      # Anything else is value
    \\r                     # But don't include the \r
    $                       # Value goes to the end of the line
""",re.VERBOSE|re.MULTILINE)

# Regular expression for parsing headers with key=value parameters
PARM_PARSER = re.compile("""
                            # VERBOSE enables this commented syntax
    [ ]*                    # allow spaces before the parm
    (?P<key>                # first parse the key from key=value pair
        ([^,= ]*)           # key is anything but comma, = or space
    )
    [ ]*=?[ ]*              # the =, possibly with surrounding whitespace
    (?P<value>              # now parse the value part
        ("[^"]*") |         # double-quoted string as value, or
        ('[^']*') |         # single-quoted string as value, or
        ([^,; ]*)           # non-quoted string as value
    )?                      # the value may be missing
    (?:[ ]*[,; ][ ]*)?      # delimeter between parms: space , or ; with
                            # optional surrounding whitespace
""",re.VERBOSE)

# Regular expression for parsing Etag header values
ETAG_PARSER = re.compile("""
                            # VERBOSE enables this commented syntax
    [ ]*                    # allow spaces before the parm
    ([Ww]/)?                # we are allowed to ignore "weak" etags
    (?P<etag>               # get the etag value
        ("[^"]*") |         # etag value is a double-quoted string
        (\*)                # or a plain old asterisk
    )
    [ ]*                    # optional trailing whitespace
""", re.VERBOSE)

# Regular expression for parsing a Range header
RANGE_PARSER = re.compile("""
                            # VERBOSE enables this commented syntax
    ^[ ]*                   # allow spaces before the parm
    (?P<unit>               # get the range unit
        ([^\d\-= ]*)        # anything but =, -, space, or a digit
    )
    [ ]*=?[ ]*              # the = is optional in CAStor (which is non-standard HTTP)
    (?P<start>              # start position
        (\d)*               # which is a sequence of 0 or more digits
    )
    (-)[ ]*                 # the dash is always required
    (?P<end>                # end position
        (\d)*               # which is a sequence of 0 or more digits
    )
    [ ]*$                   # optional trailing whitespace
""", re.VERBOSE)

# Regular expression for parsing a Castor-Authorization header
AUTH_PARSER = re.compile(r"""
    (?P<methodOp>                         # 'op =' expression
       (?P<opType>view|change|            # generic ops
                  post|put|copy|          # explicit ops
                  append|get|head|
                  delete)
                  \s*=\s*                 # whitespace okay around =
       (?P<opRealm>[a-zA-Z0-9_@].*$)?) |  # optional realm after =
    (?P<realmName>[a-zA-Z0-9_@].*$)       # default realm name
""", re.VERBOSE+re.IGNORECASE)

RE_WHITESPACE = re.compile("\s*")

RE_QPAT=re.compile(r"^\s*(?P<name>[^;]+)(\s*;\s*q=(?P<val>[0-9\.]+))?\s*$")

VALID_DOMAIN_NAME = re.compile('^[a-zA-Z0-9][0-9a-zA-Z_.-]*$')
DOMAIN_ERR_STRING = "Illegal character in domain name '%s' (not A-Z, a-z, 0-9, -, _ or .)"

def parseParms(parmStr):
    """Return a dictionary of parameters from a header value string.
    Keys are lower case, values are original case.
    parmStr = parameter string to parse (part of a header value)"""
    parms = {}
    scanned = 0
    s_end = -1
    while True:
        if scanned == len(parmStr) or s_end == 0:
            break
        tkns = PARM_PARSER.search(parmStr[scanned:])
        s_start, s_end = tkns.span()
        scanned += s_end
        key = tkns.group('key').lower()
        value = tkns.group('value')
        if not value:
            value = True
        elif value[0] in ['"', "'"] and value[-1] in ['"', "'"]:
            value = value[1:-1]
        if key:
            parms[key] = value
    return parms

def printable(s):
    """Remove any non-printable characters and return the rest"""
    chrs = [c for c in s if c in string.printable]
    newString = ''.join(chrs)
    if len(newString) > 50:
        newString = newString[:50] + '...'
    return newString

def conditional(cond, on_true, on_false):
    if cond:
        if not isfunction(on_true):
            return on_true
        else:
            return apply(on_true)
    else:
        if not isfunction(on_false):
            return on_false
        else:
            return apply(on_false)

def boundaryHeader(boundary,rng,totalLen,contentType):
    """Returns a boundary separator and headers to be included in a multipart/byteranges
       response. http://www.w3.org/Protocols/rfc2616/rfc2616-sec19.html """
    s = "--"+boundary+"\r\n"
    s += "Content-Type: "+contentType+"\r\n"
    s += "Content-Range: bytes "+str(rng[0])+"-"+str(rng[1])+"/"+str(totalLen)+"\r\n\r\n"
    return s

def finalBoundaryHeader(boundary):
    """Returns the boundary separator that ends a multipart/byteranges response.
       http://www.w3.org/Protocols/rfc2616/rfc2616-sec19.html """
    return "--"+boundary+"--\r\n"

class MetaDataDictionary(object):
    """A wrapper for a collection of HTTP header-like metadata.

    I contain an ordered mapping of names to ordered arrays of string
    values and provide dictionary-like protocol for adding and
    accessing."""

    __slots__ = ["_pairs", "_keys"]

    def __init__(self, s=None, trim=False):
        """Constructor.  The optional argument is an unparsed 
           representation with no irregularities.  Do not use
           this argument for client-supplied metadata parsing.
           Use MetaDataCollector instead.
           If trim is True, the passed string is trimmed before
           use."""
        self._pairs = []   # (original key, value, lower-cased key)
        self._keys = set() # lower-cased key
        if s and not s.startswith(CRLF):
            if trim:
                pos = s.find("\r\n\r\n")
                if pos < 0:
                    raise ValueError("passed data is not terminated")
                s = buffer(s, 0, pos+1) # We want the first \r
            for match in re.finditer(METADATA_LINE_PARSER, s):
                self.__setitem__(*match.group(1, 2))

    def copy(self):
        """Return a (shallow) copy of a MetaDataDictionary"""
        theCopy = MetaDataDictionary()
        theCopy._pairs = copy.copy(self._pairs)
        theCopy._keys = copy.copy(self._keys)
        return theCopy

    def getAll(self, name, default=None):
        key = name.lower()
        if key not in self._keys:
            # quick exit for common case
            return default
        result = [val[1] for val in self._pairs if val[2] == key]
        return result or default

    # std dict get (useful because it does not throw except if item does not exist)
    # Unlike the std dictionary method, this returns only the first item in the value list
    def get(self, name, default=None):
        return self.getAll(name, [default])[0]

    def __contains__(self, item):
        if type(item) == MetaDataDictionary:
            result = True
            for key in item._keys:
                if key not in self._keys:
                    return False
                else:
                    return ', '.join(self.getAll(key, [])) == ', '.join(item.getAll(key, []))
        else:
            result = (item.lower() in self._keys)
        return result

    def __eq__(self, other):
        return (self in other) and (other in self)

    def __getitem__(self, name):
        name = name.lower()
        result = [val[1] for val in self._pairs if val[2] == name]
        if len(result) == 0:
            raise KeyError
        return result

    def __setitem__(self, name, value):
        key = name.lower()
        self._keys.add(key)
        self._pairs.append((name, value, key))

    def __delitem__(self, name):
        key = name.lower()
        if key in self._keys:        # just do nothing if it's not there
            self._pairs = [pair for pair in self._pairs if pair[2] != key]
            self._keys.remove(key)

    def __iter__(self):
        return [(pair[0], pair[1]) for pair in self._pairs].__iter__()

    def __len__(self):
        return len(self._keys)

    def __str__(self):
        """@return a multi-line string containing HTTP-style headers based on the metadata here. The list of headers
        will be returned in the same order in which they were added or replaced."""
        buf = io.StringIO()
        for name, value, key in self._pairs:
            a = name
            b = value
            # Must handle unicode strings
            if type(a) == unicode:
                a = a.encode('utf-8')
            if type(b) == unicode:
                b = b.encode('utf-8')
            buf.write("%s: %s\r\n" % (a, b))
        return buf.getvalue()

    addValue = __setitem__

    def keys(self):
        return list(self._keys)

    def keysByPrefix(self, prefix):
        prefix = prefix.lower()
        return [k for k in self._keys if k.startswith(prefix)]

    def replaceValue(self, name, value):
        del self[name]
        self[name] = value

    def replaceValues(self, name, values):
        """@values is an array of strings"""
        del self[name]
        for val in values:
            self[name] = val

    def replaceSubset(self, subset):
        '''Add all the items from subset into self, replacing any items that had the same key'''
        if id(self) == id(subset):
            # can't replace with myself
            # it causes a nasty hang if we try
            return

        for key in subset.keys():
            del self[key]

        self.combine(subset)

    def combine(self, md1):
        """Add all the items from md1 into self"""
        if id(self) == id(md1):
            # can't combine with myself
            # it causes a nasty hang if we try
            return
        for key, val in md1:
            self[key]=val

    def transform(self, filterFunc=None, sortFunc=None, useDefaultSort=False):
        """
        Returns a transformed copy of the dictionary.
         @filterFunc, if provided, will be called with the name and value as arguments.
        Returning None from that function will cause the item to not be copied to the new
        dictionary.  Returning a different value than the one passed in will cause the
        new value to replace the old in the transformed dictionary.
         @sortFunc, if provided will be used as the cmp arg to the sort call of a list of
        name/value pair tuples.
         @useDefaultSort, if True, and if sortFunc is not provided will cause the
        dictionary's pairs to be sorted using the default Python sort.
        """
        result = MetaDataDictionary()
        if filterFunc:
            result._keys = set()
            result._pairs = []
            for name, value, key in self._pairs:
                value = filterFunc(name, value)
                if value is not None:
                    result._pairs.append( (name, value, key) )
                    result._keys.add(key)
        else:
            result._keys = copy.copy(self._keys)
            result._pairs = copy.copy(self._pairs)

        if sortFunc:
            result._pairs.sort(sortFunc)
        elif useDefaultSort:
            result._pairs.sort()

        return result

# ################################################################
# Multiple header values
# See http://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.2
# ################################################################

    def splitValues(self, headerName):
        """Convert comma-separated list values into separate header values.
        --Example--
        MyHeader: Foo, Bar
        ...becomes...
        MyHeader: Foo
        MyHeader: Bar"""
        vals = []
        for s in self.getAll(headerName, vals):
            for v in s.split(','):
                vals.append(v.strip())
        if vals:
            del self[headerName]
            for val in vals:
                self[headerName] = val

    def combineValues(self, headerName):
        """Convert multiple header values into a single, comma-separated value.
        --Example--
        MyHeader: Foo, Bar
        MyHeader: hello, world
        ...becomes...
        MyHeader: Foo, Bar, hello, world"""
        vals = self.getAll(headerName, [])
        if vals:
            del self[headerName]
            self[headerName] = ', '.join(vals)

    def getAllValues(self, headerName, toLower=True):
        """Return a list of all header values, including comma separated values,
        for a given headerName. Values are converted to lower case by default."""
        # Note that this commonly used function has been optimized
        vals = []
        headerName = headerName.lower()
        if headerName in self._keys:
            for name, value, key in self._pairs:
                if headerName == key:
                    for v in value.split(','):
                        if toLower:
                            vals.append(v.strip().lower())
                        else:
                            vals.append(v.strip())
        return vals

    def getSubsetByPrefix(self, headerNamePrefix):
        """Return a subset of this MetaDataDictionary containing only those entries
        where the name begins with the given prefix."""
        headerNamePrefix = headerNamePrefix.lower()

        def prefixFilter(name, value):
            if name.lower().startswith(headerNamePrefix):
                return value

            return None

        return self.transform(filterFunc=prefixFilter)

    def hasHeaderValue(self, headerName, headerValue):
        """Return whether headerValue is one of the comma separated values
        in any header named headerName."""
        # Note that this commonly used function has been optimized
        headerName = headerName.lower()
        if headerName in self._keys:
            headerValue = headerValue.lower()
            for name, value, key in self._pairs:
                if key == headerName:
                    for v in value.split(','):
                        if headerValue == v.strip().lower():
                            return True
        return False

# ################################################################
# Convenience methods to create and parse certain types of HTTP
# and CAStor headers.
# ################################################################

    def addLifepoint(self, constraints, start=None, end=None, seconds=0, minutes=0, hours=0, days=0, weeks=0, months=0, years=0):
        """Convenience method to construct a lifepoint header and add
        it.

        If any of the seconds, minutes, etc. increments are supplied, the end date of the
        lifepoint is calculated by adding these values to the 'start' date, if given, or
        the current date if 'start' is not supplied.  If none of the increments have
        non-zero values, the use the 'end' date. If none of the optional parameters
        are supplied, a lifepoint is added whose end date is None, which makes it the last
        lifepoint in the lifecycle of the object.

        @constraints is a comma-separated string of name/value pairs
        @start is a float similar to that returned by time.gmtime()
        @end is a float similar to that returned by time.gmtime()
        @seconds is a number of seconds to add to start to
            obtain the end-date of the lifepoint
        @minutes..years are similar to seconds

        Note: granularity of lifepoint endDates is one second"""
        if seconds or minutes or hours or days or weeks or months or years:
            if start is None:
                start = int(time.time())
            end = start
            end += seconds
            end += minutes * 60
            end += hours * 60 * 60
            end += days * 24 * 60 * 60
            end += weeks * 7 * 24 * 60 * 60
            end += months * 4 * 7 * 24 * 60 * 60
            end += years * 365 * 24 * 60 * 60
        if end is not None:
            endStr = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(end))
        else:
            endStr = ''
        lpStr = "[%s] %s" % (endStr, constraints)
        self.addValue('lifepoint', lpStr)

    mimetypes.add_type('ico', 'image/x-icon') # this is non-standard, but ubiquitous

    def guessContentType(self, path, defaultType='text/html'):
        """Add headers for Content-type and Content-encoding associated
        with the file extension found in path, which can be a file name or
        a full URL."""
        tp, encoding = mimetypes.guess_type(path, False)
        if not tp:            # use the default if we can't guess it
            tp = defaultType
        self.addValue('Content-type', tp)
        if encoding is not None:
            self.addValue('Content-encoding', encoding)

    def splitBodyParts(self, body):
        """Splits given body string and returns it as a list of parts. Each part is a Part
           object that has headers, accessed via get('header-name'), and a body, accessed via
           get_payload(). This object's Content-type should begin with "multipart/byteranges"
           and specify the boundary string.
           http://www.w3.org/Protocols/rfc2616/rfc2616-sec19.html"""
        class Part(object):
            def __init__(self, md, data):
                self._metaData = md
                self._payload = data

                self.get = self._metaData.get

            def get_content_type(self):
                return self._metaData.get('Content-Type')

            def get_payload(self):
                return self._payload

        boundary = re.match('.*boundary=([^;]+)', self.get('Content-Type')).group(1)
        parts = []

        for data in [content[2:-2] for content in body.split('--' + boundary)][1:-1]:  # first and last are false matches
            mdc = MetaDataCollector()
            oldIdx = idx = 0
            crlfPos = data.find(CRLF, idx)

            while -1 != crlfPos:
                oldIdx, idx = idx, crlfPos + len(CRLF)
                mdc.collect(data[oldIdx:idx])

                if not mdc.collecting:
                    break

                crlfPos = data.find(CRLF, idx)

            parts.append(Part(mdc.metaData, data[idx:]))

        return parts

# ################################################################
# Entity tag headers
# ################################################################

    def addContentMD5(self, digester):
        """Format and add a Content-MD5 header.

        The 'digester' parameter should be an instance of an MD5 digester.
        A common mistake here is to b64encode the hexdigest.  Hopefully, this
        helper method will make this easier to get right."""
        self.addValue('Content-MD5', base64.b64encode(digester.digest()))

    def checkContentMD5(self, digester):
        """Validate a Content-MD5 header.lower

        The 'digester' parameter should be an instance of an MD5 digester.
        A common mistake here is to b64encode the hexdigest.  Hopefully, this
        helper method will make this easier to get right.
        This method returns True if the digester matches the Content-MD5 header,
        and False otherwise."""
        headerMD5 = self.get('Content-MD5', None)
        return headerMD5 == base64.b64encode(digester.digest())

# ################################################################
# Cache-Control headers
# ################################################################

    def getCacheControlParms(self):
        """Return a dictionary of parameters from all Cache-Control headers.

        Parm keys are all lower case"""
        self.combineValues('Cache-Control')
        header = self.getAll('Cache-Control', [None])[0]
        if header:
            parms = parseParms(header)
        else:
            parms = {}
        return parms

# ################################################################
# Entity tag headers
# ################################################################

    def getAllEtags(self, headerName):
        """Return a list of all etag values, including comma separated values, for a given headerName.

        Double quotes and 'weak' modifiers are stripped."""
        etags = []
        for s in self.getAll(headerName, etags):
            for v in s.split(','):
                tkns = ETAG_PARSER.search(v)
                if tkns:
                    etags.append(tkns.group('etag'))
        return etags

    def hasEtagValue(self, headerName, etag):
        """Return whether etag is one of the comma separated etags in any header named headerName.

        This is a case-sensitive string compare.  Double quotes are inserted around the etag
        value before comparing if they're not present already.
        """
        etags = self.getAllEtags(headerName)
        if '*' in etags:
            return True
        etag = etag.strip()
        if not etag.startswith('"'):
            etag = '"%s"' % etag
        return etag in etags

# ################################################################
# Location headers
# ################################################################

    def addLocation(self, netloc, uuidString, queryArgs={}):
        """ Convenience method to construct a location header and add
            it.  See addHash and getHashParms for related convenience
            methods.
         """
        path = "/"+uuidString
        args = []
        for arg in queryArgs.items():
            args.append("%s=%s" % arg)
        query = ''
        if args:
            query = "&".join(args)
        locationURL = urlparse.urlunsplit(('http', netloc, path, query, ''))
        self.addValue("Location", locationURL)

    def parseLocation(self, location=None):
        """ @return tuple: (netLoc, uuidString, qaDict)
        """
        if location is None:
            location = self.get("Location", None)
        if location is None:
            return '', '', {}
        p = urlparse.urlsplit(location)
        qaDict = {}
        if p[3]:
            qaDict = cgi.parse_qs(p[3])
        #print 'qaDict == %s' % qaDict
        return p[1], (p[2])[1:], qaDict

    def addHash(self, hashType, hashValue):
        """ Encode hash information into location headers.
        """
        assert "Location" in self, "hash encoding requires a location header"
        locHeaders = self["location"]
        for i in xrange(len(locHeaders)):
            loc = locHeaders[i]
            p = urlparse.urlparse(loc)
            args = p[4]
            if args:
                args += '&'
            args += 'hashtype=%s&hash=%s' % (hashType, hashValue)
            locHeaders[i] = urlparse.urlunparse((p[0], p[1], p[2], p[3], args, p[5]))
#            locHeaders[i] = urlparse.urlunparse((p.scheme, p.netloc, p.path, p.params, args, p.fragment))
        self.replaceValues('Location', locHeaders)

    def getHashParms(self):
        """ returns dict of <hasharg>:[hashargValues] found in a location header urls
            where hasharg in ['hash', 'hashtype', 'newhash']. If no hashargs, returns {}"""
        ret = {}
        locHeaders = self["location"]
        for url in locHeaders:
            p = urlparse.urlsplit(url)
            if p[3]:
                qaDict = cgi.parse_qs(p[3])
                for key, val in qaDict.items():
                    if key in ["hash", "hashtype", "newhash"]:
                        ret[key]=val
        return ret

# ################################################################
# HTTP Basic Authentication
# See http://www.faqs.org/rfcs/rfc2617.html
# ################################################################

    def addBasicAuthChallenge(self, realm):
        """Construct an authentication challenge using the basic auth scheme.
        SERVER side"""
        self.addValue('WWW-Authenticate', 'Basic realm="%s"' % realm)

    def getBasicAuth(self):
        """Return username and password strings from a Basic authorization header, if it exists.
        SERVER side"""
        auth = self.get('Authorization', '')
        parts = auth.split()
        if (len(parts) >= 2) and (parts[0].lower() == 'basic'):
            decodedpwd = base64.b64decode(parts[1])
            # we don't use split(':') here because the pwd might contain a colon
            colonpos = decodedpwd.find(':')
            if colonpos > 0:
                return (decodedpwd[:colonpos], decodedpwd[colonpos+1:])
        return ('', '')

    def addBasicAuth(self, user, password):
        """Construct a Basic authorization header from user name and password.
        CLIENT side"""
        encodedAuth = base64.b64encode('%s:%s' % (user, password))
        self.addValue('Authorization', 'Basic %s' % encodedAuth)

# ################################################################
# HTTP Digest Authentication
# See http://www.faqs.org/rfcs/rfc2617.html
# TODO: Support quality of protection (qop) schemes other than 'auth'?
# ################################################################

    def addDigestAuthChallenge(self, realm, nonce, opaque='', reprompt=True):
        """Construct an authentication challenge using the digest auth scheme.
        SERVER side"""
        # this seems assbackwards to me. 'stale=true' means don't reprompt for username/password
        stale = conditional(reprompt, 'false', 'true')
        if opaque:
            self.addValue('WWW-Authenticate', 'Digest realm="%s", nonce="%s", opaque="%s", stale=%s, qop="auth", algorithm=MD5' %
                      (realm, nonce, opaque, stale))
        else:
            self.addValue('WWW-Authenticate', 'Digest realm="%s", nonce="%s", stale=%s, qop="auth", algorithm=MD5' %
                      (realm, nonce, stale))

    def addAuthInfo(self, nextNonce, parms=None):
        """Construct an authentication info header to pass back the next server nonce.
        A server may choose to return this header with a response.
        Also provides symmetric authentication of the server back to the client is parms is provided.
        nextNonce = the nonce value to use with the next request
        parms = dictionary of parameters from the Authorization header of the request
        SERVER side"""
        if parms:
            # we use the values returned in the Authorization header from the client to
            # symmetrically authenticate the server
            pNonce = parms.get('nonce', '')
            pNonceCount = parms.get('nc', '')
            pCNonce = parms.get('cnonce', '')
            pUri = parms.get('uri', '')
            pHA1 = parms.get('ha1', '')
            # digest is just like for a request except there is no method
            digest, ha1, ha2 = self.computeAuthDigest(pNonce, pNonceCount, pCNonce, uri=pUri, password=pHA1)
            self.addValue('Authentication-Info', 'nextnonce="%s", qop="auth", rspauth="%s", cnonce="%s", nc=%s' %
                          (nextNonce, digest, pCNonce, pNonceCount))
        else:
            self.addValue('Authentication-Info', 'nextnonce="%s", qop="auth"' % nextNonce)

    def getDigestAuth(self):
        """Return a dictionary of parameters from a Digest authorization header, if it exists.
        SERVER side"""
        return self._getDigestParms('Authorization')

    def addDigestAuth(self, username, password, nc, cnonce, method, parms, uri=''):
        """Construct a Digest authorization header from required information.
        username = user name
        password = clear text password or ha1 password digest
        nc = nounce count (positive integer < 2**32)
        cnonce = client nonce
        method = HTTP method being requested
        parms = parameters from the WWW-Authenticate header (must include realm and nonce)
        uri = entity being requested (defaults to uri from parms if not provided)
        CLIENT side"""
        assert(parms)
        pRealm = parms.get('realm', '')
        pNonce = parms.get('nonce', '')
        assert(pRealm and pNonce)
        pOpaque = parms.get('opaque', '')
        pUri = parms.get('uri', '')
        hexnc = hex(nc)[2:]
        if hexnc.endswith('L'):
            hexnc = hexnc[:-1]
        if len(hexnc) > 8:
            raise ValueError('Nonce count must be no more than 8 hex digits')
        hexnc = hexnc.zfill(8)

        digest, ha1, ha2 = self.computeAuthDigest(pNonce, hexnc, cnonce, \
                                        method=method, uri=(uri or pUri), \
                                        username=username, realm=pRealm, password=password)
        headerStr = 'Digest username="%s", realm="%s", nonce="%s", nc=%s, cnonce="%s", uri="%s", response="%s", qop="auth"' \
                      % (username, pRealm, pNonce, hexnc, cnonce, (uri or pUri), digest)
        if pOpaque:
            headerStr += ', opaque="%s"' % pOpaque
        self.addValue('Authorization', headerStr)

    def getDigestAuthChallenge(self):
        """Return a dictionary of parameters from a Digest authentication challenge, if it exists.
        CLIENT side"""
        return self._getDigestParms('WWW-Authenticate')

    def getAuthInfo(self):
        """Return a dictionary of parameters from an authentication info header, if it exists.
        CLIENT side"""
        # note this doesn't call getDigestParms because this header doesn't include an authtype
        header = self.get('Authentication-Info', '').strip()
        return parseParms(header)

    def computeAuthDigest(self, nonce, nc, cnonce, qop='auth', \
                               username='', realm='', password='', \
                               method='', uri='', ha2=''):
        """Compute the digest value as per rfc2617. Return digest, ha1, and ha2.
        SERVER and CLIENT side
            Note: password can be a clear text password or ha1 digest
        """
        assert password
        assert(ha2 or uri) # must provide either hashed A2 or uri (no method for response digests)

        def isDigest(s):
            if len(s) != 32:
                return False
            for c in s:
                if c not in string.hexdigits:
                    return False
            return True

        if isDigest(password):
            ha1 = password
        else:
            a1 = ':'.join([username, realm, password])
            ha1 = MD5(a1).hexdigest()
        if not ha2:
            a2 = ':'.join([method, uri])
            ha2 = MD5(a2).hexdigest()
        s = ':'.join([ha1, nonce, nc, cnonce, qop, ha2])
        return MD5(s).hexdigest(), ha1, ha2

    def _getDigestParms(self, authHeader):
        """Return a dictionary of parameters from a Digest header."""
        header = self.get(authHeader, '').strip()
        parmsPos = header.lower().find('digest ')
        if parmsPos >= 0:
            parmStr = header[parmsPos+len('digest'):]
            return parseParms(parmStr)
        else:
            return {}


# ################################################################
# Castor-Authorization headers (content level auth)
# ################################################################
    def getAllAuthRealms(self, authString=None):
        if not 'Castor-Authorization' in self and not authString:
            return ''
        realms = []
        if not authString:
            # get all auth spec strings, preserving case
            specs = self.getAllValues('Castor-Authorization', toLower=False)
        else:
            specs = []
            for v in authString.split(','):
                specs.append(v.strip())

        # parse the specs
        pSpecs = []  # parsed auth specs
        for spec in specs:
            pSpec = AUTH_PARSER.match(spec)
            if pSpec:
                pSpecs.append(pSpec)
        for pSpec in pSpecs:
            #opType = pSpec.group("opType")
            opRealm = pSpec.group("opRealm")
            realmName = pSpec.group("realmName")
            if opRealm:
                realms.append(opRealm)
            elif realmName:
                realms.append(realmName)
        return realms

    def checkAuthSyntax(self, authString=None):
        """ Check syntax of Castor-Authorization headers
            These are the patterns trapped:
               1) illegal http method:
                  nonhttpmethod=realm
               2) missing comma:
                  <METHOD>=realm <METHOD>=realm
               3) illegal domain name:
                  domain has spaces/bucket
                  NB: domain names can only be validated if a bucket
                      is present otherwise we can't distinguish it
                      from a non-domain realm (CAStor administrator,
                      CAStor operator)
            @authString - use this to validate a string otherwise
                          the string will be pulled from CA headers
            @return '' if okay otherwise an error string

        """
        if not 'Castor-Authorization' in self and not authString:
            return ''
        error = ''
        if not authString:
            # get all auth spec strings, preserving case
            specs = self.getAllValues('Castor-Authorization', toLower=False)
        else:
            specs = []
            for v in authString.split(','):
                specs.append(v.strip())

        # parse the specs
        pSpecs = []  # parsed auth specs
        for spec in specs:
            pSpec = AUTH_PARSER.match(spec)
            if pSpec:
                pSpecs.append(pSpec)
        for i, pSpec in enumerate(pSpecs):
            opType = pSpec.group("opType")
            opRealm = pSpec.group("opRealm")
            realmName = pSpec.group("realmName")
            ##print "realmName '%s'" % realmName
            ##print "opType '%s'" % opType
            ##print "opRealm '%s'" % opRealm
            if opRealm and "=" in opRealm and opType:
                error = "Syntax error, missing comma in expression: '%s'." % \
                          specs[i]
            elif realmName and "=" in realmName:
                parts = realmName.split("=")
                error = "Invalid operation type '%s' in expression: '%s'" % \
                        (parts[0], specs[i])
            elif realmName or opRealm:
                realmName = realmName or opRealm
                ##print realmName
                parts = realmName.split("/")
                if len(parts) > 1:
                    domain = parts[0]
                    parts = domain.split("@")
                    if not VALID_DOMAIN_NAME.match(parts[0]):
                        error = DOMAIN_ERR_STRING % parts[0] + " in expression: '%s'" % \
                              specs[i]
        return error

    def getAuthRealm(self, method, authString=None):
        """ Test method against all CAStor-Authorization header values
            and return matching realm restriction if present.  Header
            values can be passed in or taken from self.

            The algorithm gives 1st priority to exact match by method, 2nd
            priority to generic op match (view, change) and if none of these
            match then it looks for a default realm. In any case where there
            are 2 possibilities (2 exact matches, 2 generic realms) the 1st
            one found returned.

            method - http request method
            authString - for parsing string already pulled from headers
            @return realm or None (None means no realm auth required)

        """
        if not 'Castor-Authorization' in self and not authString:
            return None
        method = method.lower()

        if not authString:
            # get all auth spec strings, preserving case
            specs = self.getAllValues('Castor-Authorization', toLower=False)
        else:
            specs = []
            for v in authString.split(','):
                specs.append(v.strip())

        # parse the specs
        pSpecs = []  # parsed auth specs
        for spec in specs:
            pSpec = AUTH_PARSER.match(spec)
            if pSpec:
                pSpecs.append(pSpec)

        # now search the matches for a realm
        foundRealm=None
        matchFound = False  # foundRealm=None is valid answer/match so need a separate variable

        genericOp = None
        if method in ['get', 'head']:
            genericOp = 'view'
        elif not method == 'post':
            genericOp = 'change'

        for pSpec in pSpecs:
            #log.debug("%s" % str(match.groups()))
            #print "realmName '%s'" % match.group('realmName')
            #print "opType '%s'" % match.group('opType')
            #print "opRealm '%s'" % match.group('opRealm')
            opType = pSpec.group("opType")
            if opType:
                opType = opType.lower()
            if opType == method:
                # can't get any better than this
                foundRealm = pSpec.group('opRealm')
                matchFound = True
                break
            elif genericOp and opType == genericOp and not matchFound:
                # 2nd strongest match but we still want to carry on
                # search in case an explicit match can be found
                matchFound = True
                foundRealm = pSpec.group('opRealm')
        if not matchFound:
            # no match, lets see if we can find a default realm
            for pSpec in pSpecs:
                foundRealm = pSpec.group("realmName")
                if foundRealm:
                    break
        #print "getRealm for method %s with spec '%s' matched %s" % (method, authSpecs, foundRealm)
        return foundRealm


# ################################################################
# Range Headers
# See http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.35
# ################################################################

    def addRangeHeader(self, start="", end=""):
        """Create a byte range header."""
        assert start != "" or end != "", "addRangeHeader needs a start or an end!"
        if start and end:
            s = int(start)
            e = int(end)
            if s > e:
                raise ValueError("Starting byte position must be less then ending byte position.")
        self["Range"] = "bytes=%s-%s" % (start, end)

    def parseRangeHeaders(self, maxDataLength):
        """Parse any range headers found in metadata.

        Returns a list of non-overlapping ranges,
        which are pairs of integers, sorted by
        starting offset.
        """
        ranges = []
        if not "range" in self:
            return None
        rangeheaders = self["range"]
        garbage = False
        for rangeheader in rangeheaders:
            try:
                ranges += self._parseRangeHeader(rangeheader, maxDataLength)
            except ValueError as e:
                ##print "%s is garbage %s" % (rangeheader, e)
                garbage = True
        if ranges:
            ranges = self._coalesceRanges(ranges)
            if ranges[0][0] < 0:
                raise ValueError("Range specs out of range")
        else:
            if not garbage: # only in HTTP would garbage be acceptable, but out-of-range be an error
                raise ValueError("No satisfiable ranges found")
        return ranges

    def _parseRangeHeader(self, headerval, maxDataLength):
        """
        Parse a Range header spec into ranges (not coalesced)
        @headerval the range specification
        @maxDataLength the maximum length of the resource body (excluding headers)

        """
        ranges = []
        for rangestr in headerval.split(","):

            # parse a single header
            tkns = RANGE_PARSER.search(rangestr)
            if tkns:
                if tkns:
                    rangeUnit = tkns.group('unit')
                    rangeStart = tkns.group('start')
                    rangeEnd = tkns.group('end')
                #print "Unit: ", rangeUnit, " start: ", rangeStart, " end: ", rangeEnd
                if rangeUnit and rangeUnit.lower() != 'bytes':
                    raise ValueError("Unrecognized range unit (must be 'bytes')")

                if not rangeStart:
                    # this will throw valueerror unless it's a single number (e.g. -500)
                    val = int(rangeEnd)
                    r = [max(0, maxDataLength - val), maxDataLength - 1]
                elif not rangeEnd:
                    r = [int(rangeStart), maxDataLength - 1]
                else:
                    r = [ int(rangeStart), int(rangeEnd) ]

                if r[0] > maxDataLength - 1:
                    continue # skip it
                if r[1] > maxDataLength - 1:
                    r[1] = maxDataLength - 1
                if r[0] > r[1]:  # ingnore invalid range
                    raise ValueError("Invalid range '%s' (end byte is less than beginning byte)" % rangestr)
                ranges.append(r)
            else:
                raise ValueError("Cannot parse range header")
        return ranges

    def _coalesceRanges(self, ranges):
        """
        Coalesce multiple ranges into the smallest equivalent set.
        @ranges sequence of ranges, which are two-int sequences, with start and end indices, inclusive.
        """
        result = []
        if ranges:
            ranges.sort(lambda r,s : cmp(r[0], s[0]))
            for rng in ranges:
                rangestart = rng[0]
                rangeend = rng[1]
                if rangestart > rangeend: # end before start, ignore it
                    continue

                overlaps = [ resrange for resrange in result if
                             (resrange[0] <= rangestart <= resrange[1] + 1) or
                             (rangestart- 1 <= rangeend <= resrange[1]) ]
                if overlaps:
                    for overlap in overlaps:
                        overlap[0] = min(overlap[0], rangestart)
                        overlap[1] = max(overlap[1], rangeend)
                else:
                    result.append([rangestart, rangeend])
        return result

    def getQValues(self, header):
        """
        Return a dictionary where the keys are header values and the values
        are their float q-values. Missing q values are treated as q=1.0;
        """
        if not header in self:
            return {}
        mergedQEntries = ",".join(self[header])
        qvalues = dict((name.lower(),  strval is None and 1.0 or float(strval)) for name,strval in
            ( (mo.group(1),mo.group(3)) for mo in
             (RE_QPAT.match(qval.strip()) for qval in
              mergedQEntries.split(","))
             if mo) )
        return qvalues

    def getQList(self, header):
        """
        Return a prioritized list of values, ordered by decreasing q value.

        Values with q=0 are removed from the list.
        If there is no '*;q=0' in the header values, we append a '*' onto the end
        of the qList to indicate it's okay to use a default value.
        """
        qValues = self.getQValues(header)
        kqList = [(q, k) for k,q in qValues.iteritems() if q > 0.0]
        kqList.sort(reverse=True)
        qList = [k for q,k in kqList]
        if '*' not in qValues:
            qList.append('*')
        return qList

    def selectEncoding(self, codings, header="accept-encoding"):
        """Given a possible value options list, parses the header named by acceptHeaderName
        and selects the best option of from, according to the rules set forth in RFC2616. If
        there is no acceptable value, None is returned.  A return of "identity" simply means
        that only non-encoded is allowed. The encoding will be returned lowercase."""
        if not codings:
            raise ValueError("Empty or none codings list not allowed")

        if header not in self:
            mergedQEntries = "gzip,compress"
        else:
            mergedQEntries = ",".join(self[header])

        codings = [c.lower() for c in codings]
        qvalues = dict((coding.lower(),  strval is None and 1.0 or float(strval)) for coding,strval in
            ((mo.group(1),mo.group(3)) for mo in
             (RE_QPAT.match(qval.strip()) for qval in
              mergedQEntries.split(","))
             if mo)
            if coding.lower() in codings or coding == "identity" or coding == "*")

        preferred = [(coding,qvalue) for coding,qvalue in
                      ((coding, qvalues[coding]) for coding in
                      codings
                      if coding in qvalues)
                     if qvalue > 0 and coding != "*"]

        #print "codings: %s, qvalues: %s, preferred: %s" % (codings, qvalues, preferred)

        if preferred:
            preferred.sort(cmp=lambda a,b:cmp(b[1],a[1]))
            return preferred[0][0]

        if "*" in qvalues and qvalues["*"] > 0:
            return codings[0]

        if "identity" in codings:
            if "identity" in qvalues:
                if qvalues["identity"] > 0:
                    return "identity"
                else:
                    return None
            if qvalues.get("*", 1) > 0:
                return "identity"

        return None




EMPTY_STRS=set(['','\r','\n','\r\n'])
CRLF = '\r\n'
EOLS=set(['\r','\n'])

class MetaDataCollector(object):
    """I read header information from streams and store it in a dictionary.

    My collect() method is suitable for use as a filter for the
    CAStor.disk.readAll() method or to filter metadata from any of the
    dataReceived() methods from various CAStor protocols."""

    __slots__ = [ "collecting", "metaData", "_buf", "maxLineSize", "maxHeaders", "_reader", "_lastKey" ]

    def __init__(self, maxHeaders=500, maxLineSize=32768, reader=None):
        self.collecting = True
        self.metaData = MetaDataDictionary()
        self._buf = ''
        self.maxLineSize = maxLineSize
        self.maxHeaders = maxHeaders
        self._reader = reader
        self._lastKey = None

    def collect(self, chunk):
        """Snoop data for headers and, if found, put them in the metaData dictionary.

        @chunk is a string containing metadata
        @return the original data, making this a snooping passthru filter"""
        if not chunk:
            return chunk

        if self.collecting:
            if self._buf:
                data = self._buf + chunk
            else:
                data = chunk

            lines = data.splitlines()

            # if the last line isn't a full line, put it back in the buffer
            if data[-2:] != CRLF:
                self._buf = lines.pop()

                if data[-1] in EOLS:
                    self._buf += data[-1]  # hold onto it for now...remainder of CRLF may be on its way
            else:
                self._buf = None

            for line in lines:
                self.collectLine(line)
                if not self.collecting:
                    break

        return chunk

    def collectLine(self, line):
        """Examine one line of data for a header.

        @return name of the header just added, or '' if there was no
        header, or None if I should stop collecting now"""
        if line in EMPTY_STRS or not self.collecting: # end-of-headers
            self.stopCollecting()
            return None

        if len(line) > self.maxLineSize:
            self.stopCollecting()
            raise ValueError("Header is too long (max %d chars): [%s]" % (self.maxLineSize, printable(line)))

        if line[0] in "\t ": # appears to be a header continuation
            if self._lastKey:
                valArray = self.metaData[self._lastKey]
                assert valArray
                line = line.strip()
                appendedStr = "%s %s" % (valArray[-1], line)
                valArray[-1] = appendedStr
                self.metaData.replaceValues(self._lastKey, valArray)
                return self._lastKey
            else:
                self.stopCollecting()
                raise ValueError("Non-continuation header line starts with whitespace: [%s]" % printable(line))

        else: # normal header
            parts = line.split(':', 1)
            if len(parts) == 2:
                if len(self.metaData) == self.maxHeaders:
                    self.stopCollecting()
                    raise KeyError("Too many headers. Max is %d" % self.maxHeaders)
                self._lastKey = name = parts[0].strip()
                value = parts[1].strip()
                try:
                    self.metaData[name] = value
                except KeyError:
                    raise KeyError("Illegal header name for line= [%s]" % printable(line))
                except ValueError:
                    raise ValueError("Illegal value for header= [%s]" % printable(name))
                except Exception:
                    raise
                return name
            else:
                self.stopCollecting()
                raise ValueError("Missing colon in header line: [%s]" % printable(line))

    def stopCollecting(self):
        self.collecting = False
        self._buf = None
        if self._reader:
            self._reader.stopReading()
            self._reader = None

    @staticmethod
    def formatChunkHeader(chunkSize, chunkExtension={}):
        """ I format the 1st line of a chunk and return it.
            Resulting format is chunkSizeHex [chunkExtension]
            where chunkExtension is one or more ';key=val' parameters  """

        parms = []
        parmText = ''
        for parm in chunkExtension.items():
            parms.append("%s=%s" % parm)
        if parms:
            parmText = ";"+";".join(parms)
        ret = "%x%s\r\n" % (chunkSize, parmText)
        return ret

    @staticmethod
    def parseChunkHeader(chunkHeader):
        """ I parse the 1st line of a chunk.  The first line is expected to be of the
            format chunkSizeHex [chunkExtension] CRLF.
            @return tuple (chunkSize, chunkExtensionDict). """
        split = len(chunkHeader)
        ext = {}
        if ";" in chunkHeader:
            split = chunkHeader.index(";")  # extensions start at 1st ;
            ext = parseParms(chunkHeader[split+1:-2])  # adjusted for \r\n
        chunkSize = int("0x"+chunkHeader[:split].strip(), 0)
        return (chunkSize, ext)

