#!/usr/bin/env python

'''Protocols for speaking to CAStor client applications.

The CAStor application protocol, called the Simple Content Storage Protocol or SCSP,
is described in the CAStor Application Guide and the CAStor Client Overview.

I am a simple client-side Python binding of that protocol.  I allow clients
to write, read, delete, info, update, copy, and append against the cluster.

Copyright (c) 2006-2009 by Caringo, Inc. -- All rights reserved

This is free software, distributed under the terms of
the New BSD license.

See the LICENSE.txt file included in this archive.
'''

__author__ = "Jim Dutton <jim.dutton@caringo.com>"
__created__ = "26 July 2005"
__id__ = "$Id$"

import socket, errno, urllib, string, re
from io import StringIO
from urllib.parse import urlparse

import meta
import locator

class ScspFatalIOError(IOError):
    def __init__(self, msg, err):
        IOError.__init__(self, *err.args)
        self._msg = msg

    def __str__(self):
        return 'SCSP IO Error: %s; due to: %s' % (self._msg, IOError.__str__(self))


PORT            = 80
HTTP_VERS       = 'HTTP/1.1'
USER_AGENT      = 'Swarm Client/py'
CONNECT_TIMEOUT = 360                   # Server must respond in this many seconds
MAX_REDIRECT    = 5                     # bail out after this many consecutive redirects
MAX_RECV        = 131072                # read block size
MAX_WRITE_CHUNK = 500*1024              # write block size (matches recommended CAStor minimum segment size)
MAX_NOCONTINUE  = 32768                 # writes larger than this will send Expect: 100-continue
WAIT_CONTINUE   = True                  # whether to actually wait for the continue response
TERM            = '\r\n'                # header line terminator
PERSIST         = True                  # whether to leave the socket to the server open after responses

CONNECT_CACHE_SIZE  = 200               # how many node connections can be simultaneously open

UNEXPECTED_ERROR = 500                  # just blame it on the server; we will close the connection on these

UNDETERMINED_LENGTH = -1                # The content length is unknown, chunked transfer is required

def pathEscape(path, safeBytes=''):
    # This should ONLY be used for the PATH portion of a URI (or anything that needs to be encoded as such)!
    if not path:
        return ''

    UNRESERVED_CHARS = string.letters + string.digits + '-_.!~*\'()'  # per RFC3986, sec 2.3 (Jan 2005)
    SAFE_CHARS = set(UNRESERVED_CHARS + '/' + safeBytes)

    if isinstance(path, unicode):
        path = path.encode('UTF-8')

    def _makeSafe(c):
        if c not in SAFE_CHARS:
            hexVal = hex(ord(c)).replace('0x', '')
            if len(hexVal) == 1:
                hexVal = '0' + hexVal
            return '%' + hexVal     # escape the hex vals
        return c

    return reduce((lambda x, y: x + y), [_makeSafe(c) for c in path])

PATH_UNESCAPE_RE = re.compile('%([0-9a-f]{2})', re.IGNORECASE)

def pathUnescape(path): # used elsewhere, but makes sense to have here
    def _pathUnescape(matchObj):
        nibbles = matchObj.group(1)
        return chr(int(nibbles, 16))

    return PATH_UNESCAPE_RE.sub(_pathUnescape, path)

class GetResponseFSM(object):
    '''
    Finite-state machine for getting responses and parsing them.  Individual states present two pieces of information back
    to the FSM:  whether or not the state expects more data, and what the next state is/should be.
    '''
    def __init__(self, client, requestMethod):
        self.requestMethod = requestMethod
        self.collector = meta.MetaDataCollector()
        self.respCode = None
        self.firstLine = ''
        self.response = ''
        self.bodyStartOffset = None
        self.bodyDataLength = None
        self._client = client
        self._state = None
        self._unhandledData = None

        self._transitionState(GetResponseFSM.GetRespCode)

    def run(self):
        self._client.errorConnecting = False
        data = self._state.readData()

        if not data:
            self._client.errorConnecting = True
            self._client.lastResponse = 'Unable to start conversation with CAStor'
            self._client.lastResponseCode = UNEXPECTED_ERROR
            self._client.lastResponseFirstLine = ''
            self._client.responseMetaData = meta.MetaDataDictionary()
            self.respCode = self._client.lastResponseCode
            return

        noNewData = False
        self.response += data
        while self._state and (data or noNewData):
            self._unhandledData = self._state.handleData(data)

            if not self._state.expectMore:
                self._transitionState(self._state.nextState)

            if self._state:
                if self._state.expectMore:  # the new state may or may not expect data initially
                    data = self._getData()
                    noNewData = False
                else:
                    data = ''
                    noNewData = True    # force the next iteration so we can exit cleanly if needed

        if self._state and not data:    # connection was yanked
            self._client.lastResponse = 'CAStor terminated connection unexpectedly.'
            self._client.lastResponseCode = UNEXPECTED_ERROR
            self._client.lastResponseFirstLine = ''
            self._client.responseMetaData = meta.MetaDataDictionary()
            self.respCode = self._client.lastResponseCode   # report internal server error
            return

        self._client.lastResponse = self.response
        self._client.lastResponseCode = self.respCode
        self._client.lastResponseFirstLine = self.firstLine
        self._client.responseMetaData = self.collector.metaData

    def handleStateError(self, error):
        self._client.errorOccurred(error)

    def _transitionState(self, klass):
        if klass:
            self._state = klass(self)
        else:
            self._state = None

    def _getData(self):
        if self._unhandledData:
            # All data needs to eventually be considered "handled" prior to new data being read from the wire
            data = self._unhandledData
        else:
            data = self._client.recv(MAX_RECV)
            self.response += data

        return data

    #
    # State Classes
    #
    class GetRespCode(object):
        '''
        Gets the HTTP response code from the first line in the response
        '''
        def __init__(self, fsm):
            self.expectMore = True
            self.nextState = GetResponseFSM.GetHeaders
            self._fsm = fsm

        def readData(self):
            return self._fsm._client.recv(MAX_RECV)

        def handleData(self, data):
            if self._fsm.respCode:
                # Already got response code, no need to be here
                assert not self._fsm.respCode
                self.expectMore = False
                return data

            unhandled = None

            # Process the first line of the response
            headerStart = self._fsm.response.find(TERM)

            if headerStart == 0:
                self._fsm.handleStateError('Bad response from server (missing first line contents): %s' % self._fsm.response[:50])
                self._fsm.respCode = UNEXPECTED_ERROR
                self.expectMore = False
                self.nextState = None
                return None # There's no point in waiting around for more bad data.  Note this means that the caller must discard the socket.
            elif headerStart > 0:
                self._fsm.firstLine = self._fsm.response[:headerStart]
                headerStart += len(TERM)  # jump to start of next line
                unhandled = self._fsm.response[headerStart:]  # Actual headers are handled by a different state
                try:
                    self._fsm.respCode = int(self._fsm.response.split()[1])
                    self.expectMore = False
                except:
                    # If this goes wrong for any reason, freak your freak
                    self._fsm.handleStateError('Bad response code from: %s' % self._fsm.response[:50])
                    self._fsm.respCode = UNEXPECTED_ERROR
                    self.expectMore = False
                    self.nextState = None
                    return None # There's no point in waiting around for more bad data.  Note this means that the caller must discard the socket.
            # else: need more data from server

            return unhandled

    class GetHeaders(object):
        '''
        Gets the headers from the response
        '''
        def __init__(self, fsm):
            self.expectMore = True
            self.nextState = GetResponseFSM.GetBodyData
            self._fsm = fsm

        def readData(self):
            return self._fsm._client.recv(MAX_RECV)

        def handleData(self, data):
            if not self._fsm.collector.collecting:
                # Done collecting headers, no need to be here
                assert self._fsm.collector.collecting
                self.expectMore = False
                return data

            unhandled = None
            collector = self._fsm.collector

            # Process the remainder of the headers
            collector.collect(data)

            if not collector.collecting:
                self.expectMore = False
                headerEnd = TERM + TERM
                unhandled = data[(data.find(headerEnd) + len(headerEnd)):]  # Any data beyond the headers is for the next state

                if not self._fsm.bodyDataLength:
                    # If there is a content-length header, capture content length
                    self._fsm.bodyDataLength = int(collector.metaData.get('Content-length', '0'))
                    self._fsm.bodyStartOffset = self._fsm.response.find(headerEnd) + len(headerEnd)

                    if (self._fsm.respCode in (200, 206)) or ('HEAD' == self._fsm.requestMethod):  # need to ignore body on failed HEAD requests, too
                        self.nextState = None   # Let the read/info method handle this one

            return unhandled

    class GetBodyData(object):
        '''
        Gets the body data of the response (if there is any)
        '''
        def __init__(self, fsm):
            self._fsm = fsm
            self.expectMore = not self._finishedReadingData()
            self.nextState = None   # No further processing after this state

        def readData(self):
            return self._fsm._client.recvBody(MAX_RECV)

        def handleData(self, data):
            # No special processing to do...just keep requesting more data until the expected amount has been read
            self.expectMore = not self._finishedReadingData()

            return None

        def _finishedReadingData(self):
            return len(self._fsm.response[self._fsm.bodyStartOffset:]) >= self._fsm.bodyDataLength

class Command(object):
    """Superclass of all the SCSP commands."""

    def __init__(self, client, uuid=None, alias=False, source=None, destination=None, bytes=0, metaData='', queryArgs=None, path = '', host=None, externalTimeout=600.0):
        self.client = client
        if metaData is None:
            self.metaDataString = ''
        else:
            self.metaDataString = str(metaData)
        self.bytes = bytes
        if uuid:
            uuid = str(uuid)
        self.uuid = uuid
        self.alias = alias
        self.producer = source
        self.consumer = destination or StringIO()
        self.metaData = None
        self.method = None
        self.clusterSAN = None
        self.auth = None
        self.readBuffer = ''
        self.queryArgs=queryArgs
        self.redirCount = 0
        self.path = path
        self._clientHost = host
        self._timeout = CONNECT_TIMEOUT
        self._externalTimeout = externalTimeout

        # If a Host was provided via metadata, then make sure we use that instead
        if metaData:
            #we could definitely clean this up to store self.metaData as an metaDataCollection object at init rather than as
            #a string on metaDataString. Since there are several fields on this object, though, it's best we leave this alone
            #and just parse it for the host here so that we don't break any clients.
            md = None
            if not hasattr(metaData,'replaceValue'):
                mdc = meta.MetaDataCollector()
                mdc.collect(metaData)
                md = mdc.metaData
            else:
                md = metaData
            if md and md.get('Host'):   # make sure Host is defined and non-trivial
                self._clientHost = md.get('Host')
                #we'll leave the prepare call to fix up the metadata
        if uuid:
            #sanity check on the uuid to see if somebody's using it as a url
            p = urlparse.urlsplit(uuid)
            if p[2] != uuid:
                raise ValueError('uuid must not contain any other url parts.')
            elif path:
                raise ValueError('Either uuid or path must be empty.')

    def prepare(self):
        """Get everything ready, then send the initial request to the
        cluster.

        @return response code"""
        pass

    def redirect(self):
        """A redirect response was received, repeat the request to
        another node.

        @return response code"""
        self.redirCount += 1
        result = UNEXPECTED_ERROR
        if self.redirCount <= MAX_REDIRECT:
            newLocUrl = self.client.responseMetaData['location'][0]
            #print "REDIRECT TO %s" % newLocUrl
            newHost, newPath = self.parseUrl(newLocUrl)
            # Parse path again since it may have new path. Unescape it
            # because it gets re-escaped in constructRequest() (except when
            # unit test sets doNotEscapePath, ugh).
            doNotEscapePath = hasattr(self.client, 'doNotEscapePath') and self.client.doNotEscapePath

            if doNotEscapePath:
                self.path = newPath[1:]
            else:
                self.path = pathUnescape(newPath[1:])

            colonIdx = newHost.find(":")
            if colonIdx != -1:
                newHost = newHost[:colonIdx]
            if self.getRespCode() == 301:               # this is a permanent redirect, change the primary
                self.client.clusterPAN = newHost
                self.clusterSAN = None
            elif self.getRespCode() == 305:             # external redirect, don't mess with primary or secondary
                self._timeout = self._externalTimeout
                self.clusterSAN = newHost
            else:                                       # temp redirect, just change the secondary
                self.clusterSAN = newHost
            if self._clientHost:
                self.metaData.replaceValue('Host', self._clientHost)
            else:
                self.metaData.replaceValue('Host', newHost)
            self.closeSocketMaybe()                     # or just let the server tell us whether to close
            self.sendRequest()
            result = self.getResponse()
        else:
            self.client.lastResponseCode = UNEXPECTED_ERROR
            self.client.lastResponse = 'Redirect limit exceeded (%d)' % MAX_REDIRECT
        return result

    def read(self):
        if ((not hasattr(self.consumer, 'seekable')) or self.consumer.seekable()) and (hasattr(self.consumer, 'seek')):
            # Only seek if it's supported
            self.consumer.seek(0)

        if self.client.responseMetaData.hasHeaderValue('Transfer-Encoding', 'chunked'):
            self.readChunky()
        else:
            self.bytes = int(self.client.responseMetaData.get('Content-length', '0'))
            while self.bytes:
                out = self._bufferedRead(self.bytes)
                if not out:
                    break
                self.consumer.write(out)
                self.bytes -= len(out)
        #print "read: bytes left to read %d" % self.bytes

    def readChunky(self):
        """ I read chunked encoded responses """
        collector = meta.MetaDataCollector()
        contentLength = 0
        while True:
            chunkLine = self._bufferedReadLine()
            if not chunkLine:
                raise IOError("Chunked encoding format error.  Expected chunk line.")
            chunkSize, ext = collector.parseChunkHeader(chunkLine)
            contentLength += chunkSize
            # read the chunk data
            bytesRemaining = chunkSize
            while bytesRemaining:
                out = self._bufferedRead(bytesRemaining)
                bytesRemaining -= len(out)
                self.consumer.write(out)
            if chunkSize == 0:
                break
            crlf = self._bufferedReadLine()
            if crlf != TERM:
                raise IOError("Chunked encoding format error. Expected CRLF at end of chunk")
        # manufacture Content-Length header from total chunk bytes read
        self.client.responseMetaData['Content-Length'] = str(contentLength)
        # scan trailers until CRLF line...if anything goes wrong socket will raise timeout exception
        trailers = ''
        t = self._bufferedReadLine()
        while t != TERM:
            # add trailing header to meta data
            trailers += t
            #print t
            #print "reading trailer"
            t = self._bufferedReadLine()

        #print "Trailers: ", trailers
        collector.collect(trailers)
        self.client.responseMetaData.combine(collector.metaData)

    def _bufferedRead(self, maxBytes):
        #print "buffered read %d bytes (%d buffered)" % (maxBytes, len(self.readBuffer))
        if not self.readBuffer:
            self.readBuffer = self.client.recvBody(MAX_RECV)

        if self.readBuffer:
            bytes = min(maxBytes, len(self.readBuffer))
            ret = self.readBuffer[:bytes]
            self.readBuffer = self.readBuffer[bytes:]
            return ret

        return ''

    def _bufferedReadLine(self):
        ret = ''
        if not self.readBuffer:
            self.readBuffer = self.client.recvBody(MAX_RECV)
        while True:
            if self.readBuffer and TERM in self.readBuffer:
                ofs = self.readBuffer.index(TERM) + len(TERM)
                ret = self.readBuffer[:ofs]
                self.readBuffer = self.readBuffer[ofs:]
                break
            else:
                input = self.client.recvBody(MAX_RECV)
                if not input:
                    raise IOError("Chunked encoding format error.  Malformed line.")
                else:
                    self.readBuffer = self.readBuffer + input
        return ret

    def write(self):
        """Write data to the socket.

        @return response code"""
        pass

    def error(self):
        resp = self.client.lastResponse
        self.client.errorOccurred(resp[:resp.find(TERM)], self.client.lastResponseCode)
        return self.close()

    def close(self):
        """Close up everything and retire.

        @return success code."""

        self.closeSocketMaybe()

        if 'Content-UUID' in self.client.responseMetaData:
            self.uuid = self.client.responseMetaData['Content-UUID'][0]
        if 'Content-Name' in self.client.responseMetaData:
            self.path = self.client.responseMetaData['Content-Name'][0]

        return 100

    def getCurrentNode(self):
        """Return either the primary or secondary access node."""
        node = self.clusterSAN
        if not node:
            node = self.client.clusterPAN
        return node

    def getResponse(self):
        """Get and return the next response code from the server.

        I also squirrel away the last response as well as the response
        metadata, and check to see if the server wants us to close the
        connection or not.
        """

        # The FSM does the bulk of the processing.  We just need the response code and the beginning of the body data.
        fsm = GetResponseFSM(self.client, self.method)

        fsm.run()
        self.readBuffer = fsm.response[fsm.bodyStartOffset:]

        return fsm.respCode

    def getRespCode(self):
        """Return the integer response code from the last response."""
        return self.client.lastResponseCode

    def parseUrl(self, url):
        """Parse the url and return the host/location part.

        I will also parse out the authorization string if it exists."""
        p = urlparse.urlsplit(url)
        self.auth = None
        args = {}

        if p[3]:
            for qa in p[3].split('&'):
                parts = qa.split('=', 1)

                if 1 == len(parts):
                    name = parts[0]
                    value = None
                else:
                    name, value = parts

                # get the authorization code, if it's there
                if 'auth' == name:
                    self.auth = value
                    continue

                if value:
                    value=urllib.unquote_plus(value)

                vals = args.get(name, [])

                if value is not None:
                    vals.append(value)

                args[name] = vals

        self.queryArgs = args
        return p[1], p[2]

    def prepareMetaData(self):
        """Parse the metaDataString and return a CAStor.MetaDataDictionary.

        I also add some necessary non-content headers."""

        # parse the content meta data
        collector = meta.MetaDataCollector()
        mds = self.metaDataString
        if mds:
            if mds.endswith(TERM+TERM):
                mds = mds[:len(mds)-len(TERM)]
            if not mds.endswith(TERM):
                mds += TERM
        collector.collect(mds)
        md = collector.metaData
        # add the necessary non-content headers

        if self._clientHost:
            md.replaceValue('Host', self._clientHost)
        else:
            md.replaceValue('Host', self.getCurrentNode())

        if 'User-Agent' not in md:
            md['User-Agent'] = USER_AGENT

        md.replaceValue('Content-Length', str(self.bytes))

        return md

    def closeSocketMaybe(self):
        """Close the socket connection if one is open and the server told us to."""

        md = self.client.responseMetaData
        shouldClose = not PERSIST
        if 'Connection' in md:
            tokens = md['Connection'][0].split(',')
            for tok in tokens:
                tok = tok.strip()
                if tok.endswith(','):
                    tok = tok[:len(tok)-1]
                if tok.lower() == 'close':
                    shouldClose = True
        if shouldClose:
            #print 'Closing in CloseSocketMaybe'
            self.client.closeSocket()
        else:
            self.client.releaseSocket()

    def constructQueryArgs(self):
        #urlencode works on a dict of string:string. It's not designed to
        #work on a dict of string:list, so flatten our queryArgs dict into the
        #former type and encode.
        def listit(x):
            if type(x) == list:
                return x
            else:
                return [x]

        args = self.queryArgs or {}
        argArray = [(k, v) for k in args.keys() for v in listit(args[k])]
        if self.auth:
            argArray.append(('auth', self.auth))
        doNotEscapePath = hasattr(self.client, 'doNotEscapePath') and self.client.doNotEscapePath
        if doNotEscapePath:
            # Hack for internal flag, do not escape query args. Does not handle
            # values which are a list.
            l = []
            for k,v in argArray:
                l.append(k + '=' + v)
            return '&'.join(l)
        else:
            return urllib.urlencode(argArray)

    def constructRequest(self):
        """Construct and send an SCSP message."""
        if self.isRequestChunked() and (not self.chunkedRequestSupported()):
            raise ValueError('"chunked" transfer encoding not supported for %s' % self.method)

        p = self.path or self.uuid or ''
        # Internal use only, e.g. test_scsp.Test_NamedStreams.testWeirdCharacters()
        doNotEscapePath = hasattr(self.client, 'doNotEscapePath') and self.client.doNotEscapePath
        if doNotEscapePath:
            path = p
        else:
            path = pathEscape(p)
        args = self.constructQueryArgs()

        if len(args):
            if doNotEscapePath and '?' in path:
                path += "&" + args
            else:
                path += "?" + args

        req = '%s /%s %s%s' % (self.method.upper(), path, HTTP_VERS, TERM)
        return req + str(self.metaData) + TERM

    def chunkedRequestSupported(self):
        return False

    def sendRequest(self):
        self.client.requestStarted = False
        req = self.constructRequest()
        #print 'Request: ', self.getCurrentNode(), req
        self.client.connectToHost(self.getCurrentNode(), timeout=self._timeout)
        self.client.sendall(req)
        self.client.requestStarted = True

    def isRequestChunked(self):
        return self.metaData.hasHeaderValue('Transfer-Encoding', 'chunked') or ('Trailer' in self.metaData) or (UNDETERMINED_LENGTH == self.bytes)


class RequestEntityCommand(Command):

    def __init__(self, client, uuid=None, alias=False, source=None, destination=None, bytes=0, metaData='', queryArgs=None, path = '', host=None, externalTimeout=600.0):
        Command.__init__(self, client, uuid=uuid, alias=alias, source=source, destination=destination, bytes=bytes, metaData=metaData, queryArgs=queryArgs, path=path, host=host, externalTimeout=externalTimeout)

        self.autoChunk = False
        self.trailerHeaderList = []

    def prepareMetaData(self):
        md = Command.prepareMetaData(self)

        if ('Trailer' in md) or (UNDETERMINED_LENGTH == self.bytes):
            if not md.hasHeaderValue('Transfer-Encoding', 'chunked'):
                # Only auto-chunk if the caller didn't pre-chunk the data for us
                self.autoChunk = True
                md['Transfer-Encoding'] = 'chunked'

        if md.hasHeaderValue('Transfer-Encoding', 'chunked'):
            del md['Content-Length']
            # note that this culls headers that are mentioned in the trailer
            self.trailerHeaderList = RequestEntityCommand._getTrailerList(md)

        return md

    def prepareTrailerMetaData(self):
        if self.trailerHeaderList:
            md = Command.prepareMetaData(self) # start again with the original
            return RequestEntityCommand._extractTrailers(md, self.trailerHeaderList)
        else:
            return None

    def chunkedRequestSupported(self):
        return True

    def useExpectContinue(self):
        return (WAIT_CONTINUE and (self.bytes > MAX_NOCONTINUE)) or self.isRequestChunked()

    def streamLengthIsValid(self):
        if self.bytes is None:
            return False

        return (self.bytes >= 0) or (UNDETERMINED_LENGTH == self.bytes)

    def constructRequest(self):
        req = Command.constructRequest(self)

        if self.useExpectContinue():
            return req
        else:
            # if we're not doing 100-continue, send it all
            if self.producer:
                self.producer.seek(0)
                buf = self.producer.read(self.bytes)
                return req + buf

    def write(self):
        if not self.producer:
            raise IOError('No data source provided for request body')

        self.producer.seek(0)
        bufSize = MAX_WRITE_CHUNK

        if self.autoChunk:
            # If we're given a chunk size, then try to create chunks that are that size
            bufSize = int(self.client.chunkSize) or bufSize

            if 0 >= bufSize:
                bufSize = MAX_WRITE_CHUNK

        buf = self.producer.read(bufSize)

        while buf:
            #print 'Sending...', len(buf)
            if self.autoChunk:
                buf = self.chunkify(buf)

            self.client.sendall(buf)
            buf = self.producer.read(bufSize)

        if self.autoChunk:
            # send last chunk
            self.client.sendall(self.chunkify(None))

            requestTrailers = self.prepareTrailerMetaData()

            if requestTrailers:
                self.client.sendall(str(requestTrailers) + TERM)
            else:
                # need to finish off the chunked stream
                self.client.sendall(TERM)

        return self.getResponse()

    def chunkify(self, chunkData):
        chunk = hex(len(chunkData or ''))[2:] + TERM

        if chunkData:
            chunk += chunkData + TERM

        return chunk

    @staticmethod
    def _getTrailerList(metaData):
        if 'Trailer' not in metaData:
            return None

        trailerNames = [name.strip() for name in metaData.getAllValues('Trailer')]

        for trailerName in trailerNames:
            if trailerName.lower() in ['transfer-encoding', 'content-length', 'trailer']:
                raise ValueError('%s is not a valid Trailer header value' % trailerName)
            if trailerName in metaData:
                del metaData[trailerName]

        return trailerNames

    @staticmethod
    def _extractTrailers(metaData, trailerNames):
        if not trailerNames:
            return None

        requestTrailers = meta.MetaDataDictionary()

        for trailerName in [name.strip() for name in trailerNames]:
            requestTrailers.replaceValues(trailerName, metaData.getAllValues(trailerName, toLower=False))

        return requestTrailers


class WriteCommand(RequestEntityCommand):

    def prepare(self):
        # figure out where the data is coming from
        if hasattr(self.producer, 'read'):                  # is it a file-like thingy?
            if not self.streamLengthIsValid():
                raise ValueError('exact number of bytes to be written must be given')
        else:                                               # assume it's a string then
            if not self.bytes:
                self.bytes = len(self.producer)
            self.producer = StringIO(self.producer)

        self.metaData = self.prepareMetaData()              # get the headers ready to send

        if self.useExpectContinue():
            self.metaData.addValue('Expect', '100-continue')

        if self.alias:
            self.method = 'PUT'
        else:
            self.method = 'POST'

        # send the request
        self.sendRequest()
        # get the response back from the cluster and return it
        return self.getResponse()


class CopyCommand(Command):

    def prepare(self):
        self.metaData = self.prepareMetaData()              # get the headers ready to send
        self.method = 'COPY'
        # send the request
        self.sendRequest()
        # get the response back from the cluster and return it
        return self.getResponse()

class AppendCommand(RequestEntityCommand):

    def prepare(self):
        # figure out where the data is coming from
        if hasattr(self.producer, 'read'):                  # is it a file-like thingy?
            if not self.streamLengthIsValid():
                raise ValueError('exact number of bytes to be written must be given')
        else:                                               # assume it's a string then
            if not self.bytes:
                self.bytes = len(self.producer)
            self.producer = StringIO(self.producer)

        self.metaData = self.prepareMetaData()              # get the headers ready to send

        if self.useExpectContinue():
            self.metaData.addValue('Expect', '100-continue')

        self.method = 'APPEND'
        # send the request
        self.sendRequest()
        # get the response back from the cluster and return it
        return self.getResponse()


class ReadCommand(Command):

    def prepare(self):
        # make sure we have a good destination for our bytes
        if not hasattr(self.consumer, 'write'):     # make sure it's a file-like thingy
            raise ValueError( 'destination must know how to write()')
        # get the headers ready to send
        self.metaData = self.prepareMetaData()
        # send the request
        self.method = 'GET'
        #print '%s %s %s' %(self.method, self.uuid, self.path)

        self.sendRequest()
        # get response from cluster and return it
        return self.getResponse()


class DeleteCommand(ReadCommand):

    def prepare(self):
        self.metaData = self.prepareMetaData()
        self.method = 'DELETE'
        self.sendRequest()
        return self.getResponse()

class InfoCommand(ReadCommand):

    def prepare(self):
        self.metaData = self.prepareMetaData()
        self.method = 'HEAD'
        self.sendRequest()
        return self.getResponse()

    def read(self):
        pass

class HoldCommand(RequestEntityCommand):

    def prepare(self):
        # figure out where the data is coming from
        if hasattr(self.producer, 'read'):                  # is it a file-like thingy?
            if not self.streamLengthIsValid():
                raise ValueError('exact number of bytes to be written must be given')
        else:                                               # assume it's a string then
            if not self.bytes:
                self.bytes = len(self.producer)
            self.producer = StringIO(self.producer)

        self.metaData = self.prepareMetaData()              # get the headers ready to send

        if self.useExpectContinue():
            self.metaData.addValue('Expect', '100-continue')

        self.method = 'HOLD'

        # send the request
        self.sendRequest()
        # get the response back from the cluster and return it
        return self.getResponse()

class ReleaseCommand(ReadCommand):

    def prepare(self):
        self.metaData = self.prepareMetaData()
        self.method = 'RELEASE'
        self.sendRequest()
        return self.getResponse()

class SendCommand(ReadCommand):

    def prepare(self):
        self.metaData = self.prepareMetaData()
        self.method = 'SEND'
        self.sendRequest()
        return self.getResponse()


class TestCommand(ReadCommand):

    def prepare(self):
        self.metaData = self.prepareMetaData()
        self.method = "BADMETHOD"
        self.sendRequest()
        return self.getResponse()

class SCSPClient(object):
    """I am a simple, synchronous, SCSP client.

    I process one command at a time and provide the results to the
    client application. I implement a simple state machine for each
    command that the client application requests. There are six
    states:
        PREPARE         - Open resources, prepare to send request
            normally: go to REDIRECT
            resource error: go to ERROR
        REDIRECT        - Process permanent or temporary redirects from the server
            resp in (301, 302, 305, 307): stay in REDIRECT
            resp is error: go to ERROR
            resp is 200: go to READ
            resp is 100: goto WRITE
        READ            - Read data from the server
            always: goto CLOSE
        WRITE           - Write data to the server
            resp is error: go to ERROR
            resp is 201: go to CLOSE
        CLOSE           - Close resources and wrap up
            end state
        ERROR           - Report an error from the server
            end state

        After a command completes, either successfully or not, the
        last response received from the server is availabe in my
        instance variable 'lastResponse'.  Any metadata from the last
        response can also be retrieved from my instance variable
        'responseMetaData'."""

    def __init__(self, cluster, port, connectionPool=None, host=None, connectTimeout=CONNECT_TIMEOUT, externalTimeout=600.0):
        '''
        @cluster is the domain name or ip address of a node in the cluster
        @connectTimeout is the timeout to use for all connections, *including* connections resulting from a 305 redirect
        @externalTimeout is the activity timeout for connections resulting from a 305 redirect (but not establishing the connection)
        '''
        self.cluster = cluster.strip()
        self.scspPort = port
        if self.isIPaddr(self.cluster):
            self.clusterPAN = self.cluster
        else:
            self.clusterPAN = socket.gethostbyname_ex(self.cluster)[2][0]
        self.lastResponse = None
        self.lastResponseFirstLine = ''
        self.lastResponseCode = None
        self.responseMetaData = None
        self.metaData = None
        self.sock = None
        self.sockhost = None
        self.errorHandlers = []
        self.chunkSize = MAX_WRITE_CHUNK
        
        if connectionPool == None:
            self._ownsConnectionPool = True
            self._connectionPool = locator.ConnectionPool(CONNECT_CACHE_SIZE, CONNECT_CACHE_SIZE, port, connectTimeOut=connectTimeout)
        else:
            self._ownsConnectionPool = False
            self._connectionPool = connectionPool

        self._externalTimeout = externalTimeout # non-connect timeout
        self._externalPool = locator.ConnectionPool(CONNECT_CACHE_SIZE, CONNECT_CACHE_SIZE, port, connectTimeOut=connectTimeout)
        self._activePool = self._connectionPool
        self.cmd = None
        self.errorConnecting = False
        self.requestStarted = False
        self.clientHost = host #if None, the request will use the ip address from the locator (serves as the default Host header if not defined elsewhere)
        self._socketPoolMap = {}

    def isIPaddr(self, domain):
        parts = domain.split('.')
        if len(parts) != 4:
            return False
        else:
            for part in parts:
                try:
                    int(part)
                except ValueError:
                    return False
        return True

    def addErrorHandler(self, handler):
        assert callable(handler), "handler must be callable with signature f(message, code=None)"
        if not handler in self.errorHandlers:
            self.errorHandlers.append(handler)

    def removeErrorHandler(self, handler):
        self.errorHandlers.remove(handler)

    def errorOccurred(self, message, code=None):
        if self.errorHandlers:
            for handler in self.errorHandlers:
                handler(message, code)

    def connectToHost(self, host, timeout=60):
        """Open a new socket to the given host, if there's not one already."""

        self.sock = self._activePool.getConnection(host, timeout)
        self._socketPoolMap[self.sock] = self._activePool # so we know how to release it later
        self.sockhost = host # need to copy so we can remove from pool                #IGNORE:W0201

    def closeSocket(self):
        if self.sock:
            # need to use cached host name, because if other side
            # closes before us, we can't use getpeername()
            self._socketPoolMap[self.sock].releaseConnection(self.sock, self.sockhost, True)
            del self._socketPoolMap[self.sock]
            self.sock = None
            self.sockhost = None

    def releaseSocket(self):
        if self.sock:
            close = False
            mdConnectionClose = self.metaData and self.metaData.hasHeaderValue("Connection", "close")
            if (self.lastResponseCode == UNEXPECTED_ERROR) or mdConnectionClose:
                # don't pee in the pool
                close = True

            #print "release socket (close=%s)" % close
            self._socketPoolMap[self.sock].releaseConnection(self.sock, self.sockhost, close)
            del self._socketPoolMap[self.sock]
            self.sock = None
            self.sockhost = None

    def close(self):
        self.releaseSocket()
        if self._ownsConnectionPool:
            self._connectionPool.close()
        self._externalPool.close()

    def sendall(self, data):
        #print self.sock
        #print "SENT:\n", data
        try:
            self.sock.sendall(data)
        except socket.timeout:
            self.closeSocket()
            raise
        except socket.error as e:
            # recurse to retry EAGAIN
            if e.args[0] == errno.EAGAIN:
                self.sendall(data)
            else:
                raise

    def recv(self, bytes):
        try:
            data = self.sock.recv(bytes)
        except socket.timeout:
            self.closeSocket()
            raise
        except socket.error as e:
            # recurse to retry EAGAIN
            if e.args[0] == errno.EAGAIN:
                data = self.recv(bytes)
            else:
                raise
        #print "RECEIVED:\n", data
        return data

    def recvBody(self, bytes):
        try:
            return self.recv(bytes)
        except (socket.herror, socket.gaierror):
            raise
        except (socket.error, Exception) as ex:
            raise ScspFatalIOError('Failed to read body data', ex)

    def doCommand(self):
        try:
            try:
                return self._doCommand()
            except Exception as ex:
                self.lastResponseCode = UNEXPECTED_ERROR  # forces socket to depool when release
                raise
        finally:
            self.releaseSocket()

    def prepareAndCheckConnection(self):
        while True:
            resp = self.cmd.prepare()
            if not self.errorConnecting:
                return resp
            self.closeSocket() #remove from the pool and try another on the same host.

    def _doCommand(self):
        """I implement the state machine (in code) for all command processing."""

        # Reset state that was specific to a prior 305 redirection
        if self._activePool is self._externalPool:
            self._activePool = self._connectionPool
            self.clusterSAN = None

        # prepare to command
        #print 'PREPARE'
        resp = self.prepareAndCheckConnection()
        if resp > 399:
            self.cmd.error()
            return None

        # handle redirects
        #print 'REDIRECT'
        while resp in (301, 302, 305, 307):
            if 305 == resp:
                self._activePool = self._externalPool

            resp = self.cmd.redirect()

        # move the data (if any)
        #print 'MOVE'
        if resp == 100:
            resp = self.cmd.write()
            while resp in (301, 307):
                resp = self.cmd.redirect()
                if resp < 400:
                    resp = self.cmd.write()
        
        if resp in (200, 206):
            self.cmd.read()
            if self.cmd.bytes != 0:
                raise IOError("Server closed connection prematurely")
        elif resp == 201 or resp == 202: # write already complete (usually zero-length data)
            self.cmd.read()
        elif resp >= 400:
            self.cmd.error()
            return None
        else:
            # It's a non-error response that we don't handle...let the caller handle it
            return None

        #close up shop
        #print 'CLOSE'
        if resp in (100, 200, 201, 202, 204, 206, 304):
            self.cmd.close()
        else:
            self.cmd.error()
            return None

        # return the UUID or path
        path = self.cmd.path or self.cmd.uuid or ''
        return path.lstrip('/')

    def writeAuthenticated(self, uuid, source, bytes=None, metaData='', queryArgs=''):
        """Create a new stream or a new alias in the cluster with a given UUID.

        Note: This method is for administrative use only.
        It requires proper authentication in order to work.

        @uuid is the uuid of the stream I want to create
        @source is a file-like object or a string
        @bytes is the number of bytes to be written (must be provided if source is a file)
        @metaData is a string of content headers to be prepended to the stream or an instance of
            MetaDataDictionary containing content headers
        @queryArgs is a dictionary of query strings and values to add to the request
            Note: to write a alias, queryArgs must contain a ("alias" : "yes") entry

        @return the uuid of the new stream or alias or return None if there was an error"""

        self.cmd = WriteCommand(self, uuid=uuid, source=source, bytes=bytes, metaData=metaData,
                                queryArgs=queryArgs, host=self.clientHost, externalTimeout=self._externalTimeout)   #IGNORE:W0201
        return self.doCommand()

    # ##############################################################################
    # the basic SCSP commands - this is the primary user interface to this class
    # ##############################################################################

    def write(self, source, bytes=None, metaData='', queryArgs=None, path = ''):
        """Write a new stream or a new alias to the cluster

        I may just raise any number of exceptions.

        @source is a file-like object or a string
        @bytes is the number of bytes to be written (must be provided if source is a file)
        @metaData is a string of content headers to be prepended to the stream or an instance of
            MetaDataDictionary containing content headers
        @queryArgs is a dictionary of query strings and values to add to the request
            Note: to write a alias, queryArgs must contain a ("alias" : "yes") entry

        @return the uuid of the new stream or alias or return None if there was an error"""

        self.cmd = WriteCommand(self, source=source, bytes=bytes, metaData=metaData,
                                queryArgs=queryArgs, path=path, host=self.clientHost, externalTimeout=self._externalTimeout)   #IGNORE:W0201
        return self.doCommand()

    def update(self, aliasUUID, source, bytes=None, metaData='', queryArgs=None, path = ''):
        """Update an anchor stream in the cluster with new contents.

        I may just raise any number of exceptions.

        @aliasUUID tells me the id of the alias to update.
        @source is a file-like object or a string
        @bytes is the number of bytes to be written (must be provided if source is a file)
        @metaData is a string of content headers to be prepended to the stream or an instance of
            MetaDataDictionary containing content headers
        @queryArgs is a dictionary of query strings and values to add to the request
        @return the uuid of the anchor stream or None if there was an error"""

        self.cmd = WriteCommand(self, alias=True, uuid=aliasUUID, source=source, bytes=bytes,
                                metaData=metaData, queryArgs=queryArgs, path=path, host=self.clientHost, externalTimeout=self._externalTimeout)
        return self.doCommand()

    def copy(self, aliasUUID, metaData='', queryArgs=None, path = ''):
        """Copy an existing anchor stream, perhaps supplying new metadata.

        I may just raise any number of exceptions.

        @aliasUUID tells me the id of the alias to update.
        @metaData is a string of content headers to be prepended to the stream or an instance of
            MetaDataDictionary containing content headers
        @queryArgs is a dictionary of query strings and values to add to the request
        @return the uuid of the anchor stream or None if there was an error"""

        self.cmd = CopyCommand(self, alias=True, uuid=aliasUUID,
                                metaData=metaData, queryArgs=queryArgs, path=path, host=self.clientHost, externalTimeout=self._externalTimeout)
        return self.doCommand()

    def append(self, aliasUUID, source, bytes=None, metaData='', queryArgs=None, path = ''):
        """Append new data onto an existing anchor stream.

        I may just raise any number of exceptions.

        @aliasUUID tells me the id of the alias to update.
        @source is a file-like object or a string
        @bytes is the number of bytes to be written (must be provided if source is a file)
        @metaData is a string of content headers to be prepended to the stream or an instance of
            MetaDataDictionary containing content headers
        @queryArgs is a dictionary of query strings and values to add to the request
        @return the uuid of the anchor stream or None if there was an error"""

        self.cmd = AppendCommand(self, alias=True, uuid=aliasUUID, source=source, bytes=bytes,
                                metaData=metaData, queryArgs=queryArgs, path=path, host=self.clientHost, externalTimeout=self._externalTimeout)
        return self.doCommand()

    def read(self, uuid, destination=None, queryArgs=None, metaData='', path = ''):
        """Read a stream from the cluster

        @uuid is the uuid of the stream I want to read
        @destination is a file-like object to which to write the data
        @queryArgs is a dictionary of query strings and values to add to the request
        @metaData is a string of content headers to be prepended to the stream or an instance of
            MetaDataDictionary containing content headers
        @return the uuid or None if there was an error"""

        #print 'read %s %s' %(uuid, path)
        destination = destination or StringIO()
        self.cmd = ReadCommand(self, uuid=uuid, destination=destination, metaData=metaData,
                               queryArgs=queryArgs, path=path, host=self.clientHost, externalTimeout=self._externalTimeout)
        return self.doCommand()

    def delete(self, uuid, queryArgs=None, metaData='', path = ''):
        """Delete a stream from the cluster.

        @uuid is the uuid of the stream I want to delete
        @queryArgs is a dictionary of query strings and values to add to the request
        @metaData is a string of content headers to be prepended to the stream or an instance of
            MetaDataDictionary containing content headers
        @return the uuid or None if there was an error
        """
        destination = StringIO()
        self.cmd = DeleteCommand(self, uuid=uuid, destination=destination,
                                 queryArgs=queryArgs, metaData=metaData, path=path, host=self.clientHost, externalTimeout=self._externalTimeout)
        return self.doCommand()

    def info(self, uuid, queryArgs=None, metaData='', path = ''):
        """Return metadata for a stream in the cluster.

        @uuid is the uuid of the stream I want to read
        @queryArgs is a dictionary of query strings and values to add to the request
        @metaData is a string of content headers to be prepended to the stream or an instance of
            MetaDataDictionary containing content headers
        @return the uuid or None if there was an error"""
        destination = StringIO()
        self.cmd = InfoCommand(self, uuid=uuid, destination=destination,
                               queryArgs=queryArgs, metaData=metaData, path=path, host=self.clientHost, externalTimeout=self._externalTimeout)
        return self.doCommand()

    def hold(self, source, bytes=None, queryArgs=None, metaData='', path=""):
        """Create a new hold request

        I may just raise any number of exceptions.

        @path is the name of the hold request to create
        @source is a file-like object or a string
        @bytes is the number of bytes to be written (must be provided if source is a file)
        @metaData is a string of content headers to be prepended to the stream or an instance of
            MetaDataDictionary containing content headers
        @queryArgs is a dictionary of query strings and values to add to the request
            Note: to write a alias, queryArgs must contain a ("alias" : "yes") entry

        @return the uuid of the new stream or alias or return None if there was an error"""
        self.cmd = HoldCommand(self, source=source, bytes=bytes, metaData=metaData,
                                queryArgs=queryArgs, path=path, host=self.clientHost, externalTimeout=self._externalTimeout)   #IGNORE:W0201
        return self.doCommand()

    def release(self, queryArgs=None, metaData='', path=''):
        """Delete a stream from the cluster.

        @path is the name of the hold request I want to release
        @queryArgs is a dictionary of query strings and values to add to the request
        @metaData is a string of content headers to be prepended to the stream or an instance of
            MetaDataDictionary containing content headers
        @return the uuid or None if there was an error
        """
        destination = StringIO()
        self.cmd = ReleaseCommand(self, destination=destination,
                                 queryArgs=queryArgs, metaData=metaData, path=path, host=self.clientHost, externalTimeout=self._externalTimeout)
        return self.doCommand()

    def send(self, uuid, destination=None, queryArgs=None, metaData='', path = ''):
        """Send a stream from the cluster to another cluster

        @uuid is the uuid of the stream I want to send
        @destination is a file-like object to which to write the data
        @queryArgs is a dictionary of query strings and values to add to the request
        @metaData is a string of content headers to be prepended to the stream or an instance of
            MetaDataDictionary containing content headers
        @return the uuid or None if there was an error"""

        #print 'read %s %s' %(uuid, path)
        destination = destination or StringIO()
        self.cmd = SendCommand(self, uuid=uuid, destination=destination, metaData=metaData,
                               queryArgs=queryArgs, path=path, host=self.clientHost, externalTimeout=self._externalTimeout)
        return self.doCommand()


    def test(self):
        """Send an undefined method - used for testing purposes only."""
        self.cmd = TestCommand(self)
        return self.doCommand()
