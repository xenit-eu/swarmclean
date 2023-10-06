#!/usr/bin/env python

"""Main interface for initiating a connection to a CAStor cluster and creating or executing SCSP commands.

The constructor provides initial configuration of the SCSP API.

All command methods should only be called when the factory is running
(after a successful start and before a stop).

Example:

  client = scspClient.ScspClient("node1.example.com", 80, 8, 4, 8)
  client.start()
  command = client.createNodeInfoCommand()
  client.execute()
  client.stop()

Command object vs. execution method interfaces

ScspClient provides methods for creating command objects that can execute
SCSP commands and for direct execution of the same commands. For each
command object, there is an equivalent ScspClient execution method.

For example, the following two pieces of code are equivalent:


 doInfo(scspclient, uuid):
    response = scspclient.info(uuid)
    print str(response)

and

 doInfo(scspclient, uuid):
    infoCommand = client.createInfoCommand(uuid)
    response = infoCommand.execute()
    print str(response)


Mutable vs. Non-mutable methods

This API provides separate execution interfaces for CAStor anchor streams
and regular streams. The anchor stream commands contain 'Mutable' in their
method names.

Validate mode

If setValidating(True) is called, all execution methods (write, read, etc.)
will validate their arguments instead of executing requests to CAStor.

The Path Parameter

The path parameter to the ScspClient execution methods and the
path field in ScspCommand can be used to specify the Remote Cluster
Name for remote proxy features; for named object names, including
bucket and object names; and for uuids. Note that the uuid parameter is
deprecated in this release and will be removed altogether in the next
release or the one following - please use the path parameter and property
instead.

Copyright (c) 2009 by Caringo, Inc. -- All rights reserved

This is free software, distributed under the terms of
the New BSD license.

See the LICENSE.txt file included in this archive.
"""

__author__ = "Pat Ray <pat.ray@caringo.com"
__created__ = "3rd October, 2009"
__id__ = "$Id$"

from cStringIO import StringIO
import ssl

import meta
import client
import scspCommand
import scspQueryArgs
import scspHeaders
import locator
import Queue
import castorsdkversion

CASTOR_ADMIN_AGENT = 'CAStorAdminAgent/1.0'


class ScspClient (object):
    UNDETERMINED_LENGTH = client.UNDETERMINED_LENGTH
    DEFAULT_CHUNK_SIZE = client.MAX_WRITE_CHUNK

    """Singleton client interface"""
    def __init__(self, hosts, port, maxRetries, maxSavedConnections,
                 maxRunningConnections, connectionTimeout = 60, poolTimeout = 300, locatorRetryTimeout = 0,
                 loc = None, externalTimeout=600.0, sslContext=None):
        """@hosts is a list of CAStor hosts as IP addressses or host names.
             Typically this is a single value identifying an initial node in
             the CAStor cluster. The hosts list is used if the loc parameter is None.
         @port is the port number I'll use when talking to CAStor cluster.
             Typically this is 80.
         @maxSavedConnections is the maximum number of connections that the
             connection pool should save for reuse.
         @maxRunningConnections is the maximum number of simultaneously
             running executions against CAStor that I allow.
         @maxRetries is the maximum number of times to retry a command on
             communication or server failure.
         @connectionTimeout is the activity timeout in seconds for a socket.
         @poolTimeout is the amount of time in seconds a connection can remain in the connection pool
         @locatorRetryTimeout is the length of time in seconds for which we mark one of the host
            address in hosts as not accessible once we find we can't connect to the host. 0 means
            the internal locator will never re-attempt to connect to a dead host. Useful values are
            3600 seconds or 0.
         @loc is a locator.Locator subclass. If this is None, this instance will use a default
            StaticLocator configured with the hosts parameter.
         @externalTimeout is the activity timeout to use for connections made as a result of a 305 redirect.  connectionTimeout is still used for establishing the connection, however
         @sslContext is passed when instantiating an ScspClientSSL() object.
        """
        if loc is None:
            self.locator = locator.StaticLocator(hosts, locatorRetryTimeout)
        else:
            self.locator = loc
        self.port = port
        self.maxRetries = maxRetries
        self.validateMode = False
        self.redirectCache = locator.RedirectCache()
        self.connectionPool = locator.ConnectionPool(maxSavedConnections, maxRunningConnections, port, connectionTimeout, poolTimeout, sslContext=sslContext)
        self.userAgent = 'Swarm Client python/%s (with SSL)' %(castorsdkversion.CASTORSDKVERSION)
        client.USER_AGENT = self.userAgent
        self.connectionTimeout = connectionTimeout
        self.useBackoff = True
        self.externalTimeout = externalTimeout
        self.hostHeaderValue = None
        self.chunkSize = ScspClient.DEFAULT_CHUNK_SIZE
        self._sslContext = sslContext

    def start(self):
        """Not used. This is included for consistency with the CIK Design documentation."""
        pass

    def stop(self):
        """Stop the interface and close all connections."""
        self.connectionPool.close()

    def _executeOrValidate(self, command):
        #Execute or validate a command, depending on the mode that's set for me
        if self.validateMode:
            return command.validate()
        else:
            return command.execute()

    def _executeOrValidateMutable(self, command):
        #executeorValidate with alias=yes for anchor streams.
        args = scspQueryArgs.ScspQueryArgs()
        args.addAll(command.queryArgs)
        args.setValue('alias', 'yes')
        command.queryArgs = args
        return self._executeOrValidate(command)

    def write(self, inputStream, inputStreamLength, queryArgs = None,
              metaData = None, path = ""):
        """Execute or validate a normal (non-mutable) SCSP write command.

         @inputStream is the file-like object containing data to write to CAStor.
         @inputStreamLength is the length of the input stream.
         @queryArgs is the queryArgs to pass to execution.
         @metaData is the headers to pass to execution.
         @path is the path to pass to execution.
         @return: If isValidating, this is a response with ScspResultCode set
             to ScspRCSuccess if headers and query args are valid for this
             command or ScspRCFailure otherwise. If not isValidating, this is
             the response returned from CAStor.
        """
        return self._executeOrValidate(scspCommand.ScspWrite(self, inputStream, inputStreamLength, queryArgs, metaData, path, hostHeaderValue=self.hostHeaderValue))

    def read(self, uuid, outputStream, queryArgs = None, metaData = None, path = ""):
        """Execute or validate a normal (non-mutable) SCSP read command.

         @uuid (deprecated) is the UUID of CAStor stream to read.
         @outputStream is a file-like object to write data read from CAStor.
         @queryArgs is the queryArgs to pass to execution.
         @metaData is the headers to pass to execution.
         @path is the path to pass to execution.
         @return: If isValidating, this is a response with ScspResultCode set
             to ScspRCSuccess if headers and query args are valid for this
             command or ScspRCFailure otherwise. If not isValidating, this is
             the response returned from CAStor.
        """
        return self._executeOrValidate(scspCommand.ScspRead(self, uuid, outputStream, queryArgs, metaData, path, hostHeaderValue=self.hostHeaderValue))

    def info(self, uuid, queryArgs = None, metaData = None, path = ""):
        """Execute or validate a normal (non-mutable) SCSP info command.

         @uuid (deprecated) is the UUID of the CAStor stream to retrieve info for.
         @queryArgs is the queryArgs to pass to execution.
         @metaData is the headers to pass to execution.
         @path is the path to pass to execution.
         @return: If isValidating, this is a response with ScspResultCode set
             to ScspRCSuccess if headers and query args are valid for this
             command or ScspRCFailure otherwise. If not isValidating, this is
             the response returned from CAStor.
          """
        return self._executeOrValidate(scspCommand.ScspInfo(self, uuid, queryArgs, metaData, path, hostHeaderValue=self.hostHeaderValue))


    def delete(self, uuid, queryArgs = None, metaData = None, path = ""):
        """Execute or validate a normal (non-mutable) SCSP delete command.

         @uuid (deprecated) is the UUID of the CAStor stream to delete.
         @queryArgs is the queryArgs to pass to execution.
         @metaData is the headers to pass to execution.
         @path is the path to pass to execution.
         @return: If isValidating, this is a response with ScspResultCode set
             to ScspRCSuccess if headers and query args are valid for this
             command or ScspRCFailure otherwise. If not isValidating, this is
             the response returned from CAStor.
        """
        return self._executeOrValidate(scspCommand.ScspDelete(self, uuid, queryArgs, metaData, path, hostHeaderValue=self.hostHeaderValue))

    def nodeStatus(self, queryArgs = None, metaData = None):
        """Execute or validate an SCSP info command to retrieve cluster status.

         @queryArgs is the queryArgs to pass to execution.
         @metaData is the headers to pass to execution.
         @return: If isValidating, this is a response with ScspResultCode set
             to ScspRCSuccess if headers and query args are valid for this
             command or ScspRCFailure otherwise. If not isValidating, this is
             the response returned from CAStor.
        """
        return self._executeOrValidate(scspCommand.ScspNodeStatus(self, queryArgs, metaData, hostHeaderValue=self.hostHeaderValue))

    def aggregateInfo(self, uuid, outputStream, queryArgs = None, metaData = None, path = ""):
        """Execute or validate a normal (non-mutable) SCSP Proxy aggregate info command.

         @uuid (deprecated) is the UUID of CAStor stream to query.
         @outputStream is a file-like object to write data read from the proxy.
         @queryArgs is the queryArgs to pass to execution.
         @metaData is the headers to pass to execution.
         @path is the path to pass to execution.
         @return: If isValidating, this is a response with ScspResultCode set
             to ScspRCSuccess if headers and query args are valid for this
             command or ScspRCFailure otherwise. If not isValidating, this is
             the response returned from proxy.
        """
        return self._executeOrValidate(scspCommand.ScspAggregateInfo(self, uuid, outputStream, queryArgs, metaData, path, hostHeaderValue=self.hostHeaderValue))

    def writeMutable(self, inputStream, inputStreamLength,
                     queryArgs = None, metaData = None, path = ""):
        """Execute or validate an anchor (mutable) stream SCSP write command.

         @inputStream is a file-like object containing the data to write to
             CAStor.
         @inputStreamLength is the length of the input stream.
         @queryArgs is the queryArgs to pass to execution.
         @metaData is the headers to pass to execution.
         @path is the path to pass to execution.
         @return: If isValidating, this is a response with ScspResultCode set
             to ScspRCSuccess if headers and query args are valid for this
             command or ScspRCFailure otherwise. If not isValidating, this is
             the response returned from CAStor.
        """
        return self._executeOrValidateMutable(scspCommand.ScspWrite(self, inputStream, inputStreamLength, queryArgs, metaData, path, hostHeaderValue=self.hostHeaderValue))

    def updateMutable(self, uuid, inputStream, inputStreamLength,
                      queryArgs = None, metaData = None, path = ""):
        """Execute or validate a SCSP update command.

         @uuid (deprecated) is the UUID of the CAStor stream to udpate.
         @inputStream is a file-like object containing the data to write to
             CAStor.
         @inputStreamLength is the length of the input stream.
         @queryArgs is the queryArgs to pass to execution.
         @metaData is the headers to pass to execution.
         @path is the path to pass to execution.
         @return: If isValidating, this is a response with ScspResultCode set
             to ScspRCSuccess if headers and query args are valid for this
             command or ScspRCFailure otherwise. If not isValidating, this is
             the response returned from CAStor.
        """
        return self._executeOrValidateMutable(scspCommand.ScspUpdate(self, uuid, inputStream, inputStreamLength, queryArgs, metaData, path, hostHeaderValue=self.hostHeaderValue))

    def readMutable(self, uuid, outputStream, queryArgs = None,
                    metaData = None, path = ""):
        """Execute or validate an anchor (mutable) SCSP read command.

         @uuid (deprecated) is the UUID of CAStor stream to read.
         @outputStream is a file-like object to write data read from CAStor.
         @queryArgs is the queryArgs to pass to execution.
         @metaData is the headers to pass to execution.
         @path is the path to pass to execution.
         @return: If isValidating, this is a response with ScspResultCode set
             to ScspRCSuccess if headers and query args are valid for this
             command or ScspRCFailure otherwise. If not isValidating, this is
             the response returned from CAStor.
          """
        return self._executeOrValidateMutable(scspCommand.ScspRead(self, uuid, outputStream, queryArgs, metaData, path, hostHeaderValue=self.hostHeaderValue))

    def infoMutable(self, uuid, queryArgs = None, metaData = None, path = ""):
        """Execute or validate an anchor (mutable) stream SCSP info command.

         @uuid (deprecated) is the UUID of CAStor stream to retrieve info on.
         @queryArgs is the queryArgs to pass to execution.
         @metaData is the headers to pass to execution.
         @path is the path to pass to execution.
         @return: If isValidating, this is a response with ScspResultCode set
             to ScspRCSuccess if headers and query args are valid for this
             command or ScspRCFailure otherwise. If not isValidating, this is
             the response returned from CAStor.
          """
        return self._executeOrValidateMutable(scspCommand.ScspInfo(self, uuid, queryArgs, metaData, path, hostHeaderValue=self.hostHeaderValue))

    def deleteMutable(self, uuid, queryArgs = None, metaData = None, path = ""):
        """Execute or validate an anchor (mutable) stream SCSP delete command.

         @uuid (deprecated) is the UUID of CAStor stream to delete.
         @queryArgs is the queryArgs to pass to execution.
         @metaData is the headers to pass to execution.
         @path is the path to pass to execution.
         @return: If isValidating, this is a response with ScspResultCode set
             to ScspRCSuccess if headers and query args are valid for this
             command or ScspRCFailure otherwise. If not isValidating, this is
             the response returned from CAStor.
        """
        return self._executeOrValidateMutable(scspCommand.ScspDelete(self, uuid, queryArgs, metaData, path, hostHeaderValue=self.hostHeaderValue))

    def appendMutable(self, uuid, inputStream, inputStreamLength,
                      queryArgs = None, metaData = None, path = ""):
        """Execute or validate a SCSP append command.

         @uuid (deprecated) is the UUID of the CAStor stream to append to.
         @inputStream is a file-like object containing the data to write to
             CAStor.
         @inputStreamLength is the length of the input stream.
         @queryArgs is the queryArgs to pass to execution.
         @metaData is the headers to pass to execution.
         @path is the path to pass to execution.
         @return: If isValidating, this is a response with ScspResultCode set
             to ScspRCSuccess if headers and query args are valid for this
             command or ScspRCFailure otherwise. If not isValidating, this is
             the response returned from CAStor.
        """
        return self._executeOrValidateMutable(scspCommand.ScspAppend(self, uuid, inputStream, inputStreamLength, queryArgs, metaData, path, hostHeaderValue=self.hostHeaderValue))

    def copyMutable(self, uuid, queryArgs = None, metaData = None, path = ""):
        """Execute or validate a SCSP copy command.

         @uuid (deprecated) is the UUID of the CAStor stream to copy.
         @queryArgs is the queryArgs to pass to execution.
         @metaData is the headers to pass to execution.
         @path is the path to pass to execution.
         @return: If isValidating, this is a response with ScspResultCode set
             to ScspRCSuccess if headers and query args are valid for this
             command or ScspRCFailure otherwise. If not isValidating, this is
             the response returned from CAStor.
          """
        return self._executeOrValidateMutable(scspCommand.ScspCopy(self, uuid, queryArgs, metaData, path, hostHeaderValue=self.hostHeaderValue))

    def hold(self, inputStream, inputStreamLength,
                     queryArgs = None, metaData = None, path = ""):
        """Execute or validate an anchor (mutable) stream SCSP hold command.

         @inputStream is a file-like object containing the list of streams to put
             in the hold request.
         @inputStreamLength is the length of the input stream.
         @queryArgs is the queryArgs to pass to execution.
         @metaData is the headers to pass to execution.
         @path is the path to pass to execution.
         @return: If isValidating, this is a response with ScspResultCode set
             to ScspRCSuccess if headers and query args are valid for this
             command or ScspRCFailure otherwise. If not isValidating, this is
             the response returned from CAStor.
        """
        return self._executeOrValidateMutable(scspCommand.ScspHold(self, inputStream, inputStreamLength, queryArgs, metaData, path, hostHeaderValue=self.hostHeaderValue))


    def release(self, path, queryArgs = None, metaData = None):
        """Execute or validate an anchor (mutable) stream SCSP release command.

         @path is the path to pass to execution.
         @queryArgs is the queryArgs to pass to execution.
         @metaData is the headers to pass to execution.
         @return: If isValidating, this is a response with ScspResultCode set
             to ScspRCSuccess if headers and query args are valid for this
             command or ScspRCFailure otherwise. If not isValidating, this is
             the response returned from CAStor.
        """
        return self._executeOrValidateMutable(scspCommand.ScspRelease(self, path, queryArgs, metaData, hostHeaderValue=self.hostHeaderValue))

    def send(self, uuid, outputStream, queryArgs = None, metaData = None, path = ""):
        """Execute or validate a normal (non-mutable) SCSP send command.

         @uuid (deprecated) is the UUID of CAStor stream to send.
         @outputStream is a file-like object to write data read from CAStor.
         @queryArgs is the queryArgs to pass to execution.
         @metaData is the headers to pass to execution.
         @path is the path to pass to execution.
         @return: If isValidating, this is a response with ScspResultCode set
             to ScspRCSuccess if headers and query args are valid for this
             command or ScspRCFailure otherwise. If not isValidating, this is
             the response returned from CAStor.
        """
        return self._executeOrValidate(scspCommand.ScspSend(self, uuid, outputStream, queryArgs, metaData, path, hostHeaderValue=self.hostHeaderValue))

    def createWriteCommand(self, inputStream, inputStreamLength):
        """Create a ScspWriteCommand with an input stream and length.

         @inputStream is a file-like object to read data from for writing
             to CAStor.
         @inputStreamLength is the length of the input stream.
         @return The write command ready to execute.
          """
        return scspCommand.ScspWrite(self, inputStream, inputStreamLength, hostHeaderValue=self.hostHeaderValue)

    def createUpdateCommand(self, uuid, inputStream, inputStreamLength):
        """Create a ScspUpdateCommand.

         @uuid (deprecated) is the UUID of the CAStor anchor stream to update.
         @inputStream is a file-like object to read data from for writing
             to CAStor.
         @inputStreamLength is the length of the input stream.
         @return The update command ready to execute.
        """
        return scspCommand.ScspUpdate(self, uuid, inputStream, inputStreamLength, hostHeaderValue=self.hostHeaderValue)

    def createReadCommand(self, uuid, outputStream):
        """Create a ScspReadCommand.

         @uuid (deprecated) is thhe UUID of the CAStor stream to read.
         @outputStream is a file-like object to write data read from CAStor.
         @return The read command ready to execute.
          """
        return scspCommand.ScspRead(self, uuid, outputStream, hostHeaderValue=self.hostHeaderValue)

    def createInfoCommand(self, uuid):
        """Create a ScspInfoCommand.

         @uuid (deprecated) is thhe UUID of the CAStor stream to retrieve info for.
         @return The read command ready to execute.
        """
        return scspCommand.ScspInfo(self, uuid, hostHeaderValue=self.hostHeaderValue)

    def createAggregateInfoCommand(self, uuid, outputStream):
        """Create an ScspAggregateInfoCommand.

         @uuid (deprecated) is thhe UUID of the CAStor stream to retrieve aggregateInfo for.
         @return The read command ready to execute.
        """
        return scspCommand.ScspAggregateInfo(self, uuid, outputStream, hostHeaderValue=self.hostHeaderValue)

    def createNodeStatusCommand(self):
        """Create a ScspNodeInfoCommand.

         @return The node info command ready to execute.
        """
        return scspCommand.ScspNodeStatus(self, hostHeaderValue=self.hostHeaderValue)

    def createDeleteCommand(self, uuid):
        """Create a ScspDeleteCommand.

         @uuid (deprecated) is thhe UUID of the CAStor stream to delete.
         @return The delete command ready to execute.
        """
        return scspCommand.ScspDelete(self, uuid, hostHeaderValue=self.hostHeaderValue)

    def createAppendCommand(self, uuid, inputStream, inputStreamLength):
        """Create a ScspAppendCommand.

         @uuid (deprecated) is thhe UUID of the CAStor stream to read.
         @inputStream is a file-like object to read data from for writing
             to CAStor.
         @inputStreamLength is the length of the input stream.
         @return The append command ready to execute.
        """
        return scspCommand.ScspAppend(self, uuid, inputStream, inputStreamLength, hostHeaderValue=self.hostHeaderValue)

    def createCopyCommand(self, uuid):
        """Create a ScspCopyCommand.

         @uuid (deprecated) is the UUID of the CAStor anchor stream to append to.
         @return The copy command ready to execute.
        """
        return scspCommand.ScspCopy(self, uuid, hostHeaderValue=self.hostHeaderValue)

    def createHoldCommand(self, inputStream, inputStreamLength):
        """Create a ScspHoldCommand with an input stream and length.

         @inputStream is a file-like object to read data from for writing
             to CAStor.
         @inputStreamLength is the length of the input stream.
         @return The write command ready to execute.
          """
        return scspCommand.ScspHold(self, inputStream, inputStreamLength, hostHeaderValue=self.hostHeaderValue)

    def createReleaseCommand(self):
        """Create a ScspReleaseCommand.

         @return The release command ready to execute.
        """
        return scspCommand.ScspRelease(self, hostHeaderValue=self.hostHeaderValue)

    def createSendCommand(self, uuid, outputStream):
        """Create a ScspSendCommand.

         @uuid (deprecated) is thhe UUID of the CAStor stream to read.
         @outputStream is a file-like object to write data read from CAStor.
         @return The read command ready to execute.
          """
        return scspCommand.ScspSend(self, uuid, outputStream, hostHeaderValue=self.hostHeaderValue)


class ScspClientSSLContext(object):
        """This is a stripped down version of the ssl.SSLContext from
        Python 2.7.9+. If ssl.SSLContext is available, you should use
        that and pass it to ScspClient() directly.
        
        On Linux, the single PEM file for all trusted CAs must be generated.
        For Debian-based systems: dpkg-reconfigure ca-certificates
        """
        
        def __init__(self, protocol):
            """create the stripped down SSLContext
            @protocol must be one of the ssl PROCOTOL_* constants
            """
            self._cafile = '/etc/ssl/certs/ca-certificates.crt'
            
            # set the default SSL/TLS options
            self.protocol = protocol
            self.verify_mode = ssl.CERT_REQUIRED
            self.check_hostname = True
        
        
        def wrap_socket(self, sock, server_side=False, do_handshake_on_connect=True, suppress_ragged_eofs=True, server_hostname=None):
            """minimal implementation of SSLContext.wrap_socket() that
            only implements client-side connections. Server host name
            checking only works when the socket is connected prior to
            calling this wrap method.
            @sock is a socket.socket() object
            @server_side must always be False
            @do_handshake_on_connect see ssl.wrap_socket()
            @suppress_ragged_eofs see ssl.wrap_socket()
            @server_hostname server host name or None to disable check
            
            Returns a socket as described by ssl.wrap_socket()
            
            NOTICE: Server host name checking will only be performed
            if the socket has already been connected when this method
            is called. You can call the check_hostname_against_cert()
            method after connecting your socket if you wish delay the
            connection until after wrapping it.
            """
            
            if server_side is not False:
                raise NotImplementedError("ScspClientSSLContext does not support server-side sockets")
            
            # Determine if socket has already been connected
            socketIsConnected = False
            try:
                sock.getpeername()
                socketIsConnected = True
            except socket.error as sockErrorTuple:
                # errno==107 is expected on a disconnected socket; re-raise for anything else
                if sockErrorTuple[0] != 107:
                    raise socket.error(sockErrorTuple)
            
            # Put the TLS wrapper on the bare socket
            newsock = ssl.wrap_socket(sock,
                                      server_side=False,
                                      cert_reqs=self.verify_mode,
                                      ssl_version=self.protocol,
                                      ca_certs=self._cafile,
                                      do_handshake_on_connect=do_handshake_on_connect,
                                      suppress_ragged_eofs=suppress_ragged_eofs)
            
            # Validate the peer's host name if the socket is connected
            if socketIsConnected is True and server_hostname is not None and self.verify_mode != ssl.CERT_NONE:
                self.check_hostname_against_cert(newsock, server_hostname)
            
            return(newsock)
        
        
        def load_verify_locations(self, cafile=None, capath=None, cadata=None):
            """Stripped down version of SSLContext.load_verify_locations
            @cafile file name for trusted CA bundle
            @capath not implemented
            @cadata not implemented
            """
            
            if cafile is not None:
                self._cafile = cafile
            
            # Since this isn't a full reimplementation of SSLContext, 'capath' and 'cadata' cannot be handled
            if capath is not None:
                raise NotImplementedError("ScspClientSSLContext does not support the 'capath' parameter")
            if cadata is not None:
                raise NotImplementedError("ScspClientSSLContext does not support the 'cadata' parameter")
        
        
        def check_hostname_against_cert(self, sock, hostname):
            """Verify that socket's certificate matches a given
            hostname. IP addresses are not supported. Subject Alternate
            Names are supported.
            @sock ssl socket object that has been connected
            @hostname server host name string
            
            ssl.CertificateError raised on failure. On success, the
            function returns nothing.
            """
            
            cert = sock.getpeercert()
            
            if cert.has_key('subject'):
                for field in cert['subject']:
                    if field[0][0] == "commonName":
                        if self._hostname_match(hostname, field[0][1]):
                            return  # host is valid
                        break  # no reason to keep searching after commonName
                        
            if cert.has_key('subjectAltName'):
                for field in cert['subjectAltName']:
                    if field[0] == "DNS":
                        if self._hostname_match(hostname, field[1]):
                            return  # host is valid
            
            raise ssl.CertificateError("Host name '%s' does not match certificate: %s" % (hostname, cert))
        
        
        def _hostname_match(self, hostname, pattern):
            """Match a host name against a pattern. The pattern can
            contain a leading "*." for matching SSL wildcard names.
            This function is more permissive than true SSL matching and
            "one.two.example.com" will matching against "*.example.com".
            """
            
            # exact match
            if hostname == pattern:
                return True
            
            # wildcard match
            if len(pattern) > 2 and pattern[:2] == "*.":
                if hostname.endswith(pattern[2:]):
                    return True
            
            return False
