#!/usr/bin/env python

"""Classes for handling host name lookup and sockets.

Included classes:

Locator - Provides a way to find hosts
ConnectionPool - Provides sockets and stores open sockets for reuse
RedirectCache - Provides a way to save and retrieve hosts that we've been redirected
to.

Copyright (c) 2009 by Caringo, Inc. -- All rights reserved

This is free software, distributed under the terms of
the New BSD license.

See the LICENSE.txt file included in this archive."""

__author__ = "Pat Ray <pat.ray@caringo.com"
__created__ = "3rd October, 2009"
__id__ = "$Id$"

from threading import Lock
from threading import BoundedSemaphore
import time
import socket
import ssl

class Locator(object):
    """ Base Locator interface.
    
    I provide a way to find hosts"""
    
    def locate(self):
        return ''

    def locateAll(self):
        return []

    def foundAlive(self, host):
        pass

    def foundDead(self, host):
        pass

    #do I know about host?
    def inList(self, host):
        return False

def synchronized(lock):
    """ Synchronization decorator.
    
        Found in several sources on the web.
    """
    def wrap(f):
        def newf(*args, **kw):
            lock.acquire()
            try:
                return f(*args, **kw)
            finally:
                lock.release()
        return newf
    return wrap

def locked(lock):
    """ Synchronization state check decorator."""
    def wrap(f):
        def newf(*args, **kw):
            assert(lock.locked())
            return f(*args, **kw)
        return newf
    return wrap

class StaticLocator(object):
    """Very simple round-robin host lookup. 
    
    Returns one from a list of hosts passed in to the constructor on locate(). 
    If notifyDead is called on a host, that host is placed in the dead pool 
    and removed from the host list. Periodically checks for hosts that were 
    found dead > retrytime ago and restores them to the host list.
    """
    lock = Lock()

    def __init__(self, hosts, retrytime = 0):
        """@hosts is a list of host names or IP addresses that I will offer up.
        @retrytime is the time in seconds since I found a node dead that I
        will wait before restoring it to my host list. If retrytime <= 0, then
        I never try to restore a dead node.
        """
        self._hosts = hosts
        self._retrytime = retrytime
        self._deadPool = []

    @synchronized(lock)
    def __str__(self):
        """String conversion for testing.
        
        Be careful how you call this. Since lock isn't reentrant, calling this
        from one of the synchronized methods will break everything.
        """ 
        result = 'Hosts '
        for host in self._hosts:
            result += '%s ' % host
        result += 'Dead hosts '
        for e in self._deadPool:
            result += '[%s %s] ' % (e[0], e[1])
        return result

    @synchronized(lock)
    def locate(self):
        """@return A node from my static list."""
        #remove a host from the front and put it on the end

        if self._hosts:
            host = self._hosts.pop(0)
            self._hosts.append(host)
            self._checkDeadPool()
        else:
            host = None
        return host
        
    @synchronized(lock)
    def locateAll(self):
        """@return all nodes in my static list."""

        if self._hosts:
            self._checkDeadPool()
        return self._hosts[:]   # return a copy

    @synchronized(lock)
    def foundDead(self, host):
        """Remove a host from my host list. 
        
        If the host isn't already in the
        list, ignore it. Moves the host to the dead pool with a timestamp of
        the current system time.
        
        @host is the name or IP address of the host to remove. This should
        match the name originally served up in locate.
        """
        #only move it if it's in the host list; ignore it otherwise
        if host in self._hosts:
            if len(self._hosts) > 1:
                #make sure we've always got at least one
                self._hosts.remove(host)
                if self._retrytime > 0:
                    self._deadPool.append([time.time(), host])

    #can only be called from a synchronized function
    @locked(lock)
    def _checkDeadPool(self):
        #Check the dead pool for dead nodes that are past the timeout.
        addHosts = [h for t,h in self._deadPool if time.time() > t + self._retrytime]
        self._hosts.extend(addHosts)
        self._deadPool = [[t,h] for t,h in self._deadPool if h not in addHosts]

    @synchronized(lock)
    def inList(self, host):
        return host in self._hosts

    @synchronized(lock)
    def foundAlive(self, host):
        if host not in self._hosts:
            self._hosts.append(host)

class RedirectCache(object):
    """I manage a synchronized list of host names or IP addresses."""
    
    redirectLock = Lock()

    def __init__(self):
        self._hosts = []

    @synchronized(redirectLock)
    def add(self,host):
        """Add a new host to my list of hosts."""
        if not host in self._hosts:
            self._hosts.append(host)

    @synchronized(redirectLock)
    def remove(self,host):
        """Remove a host from my list of hosts."""
        if host in self._hosts:
            self._hosts.remove(host)

    @synchronized(redirectLock)
    def get(self):
        """Get the last node from my list of hosts."""
        if len(self._hosts) > 0:
            #we want to get the last one added
            return self._hosts[len(self._hosts)-1]
        else:
            return None

    @synchronized(redirectLock)
    def __str__(self):
        return str(self._hosts)

class ConnectionPool(object):
    """I create and open sockets and store open sockets for reuse.
    
    I provide ways to limit the number of open connections in use and the
    number of saved connections.
    """
    lock = Lock()

    def __init__(self, maxSavedConnections, maxRunningConnections, port, 
                 connectTimeOut = 60, poolTimeOut = 300, sslContext=None):
        """@maxSavedConnections is the maximum number of open connections I
        will store.
        @maxRunningConnections is the maximum number of open connections I
        will hand out to clients.
        @port is the port on which I will create sockets
        @connectTimeOut is the socket connection timeout I will set on a
        newly created socket
        @poolTimeOut is the minumum amount of time since a socket was
        returned to me that I will wait before removing and closing it.
        @sslContext is an ssl.SSLContext if using SSL/TLS or None for HTTP.
        """
        self._pool = [] #list of addresses, time used, socket triples
        self._poolTimeOut = poolTimeOut
        self._port = int(port)
        self._semaphore = BoundedSemaphore(maxRunningConnections)
        self._maxSavedConnections = maxSavedConnections
        self._maxRunningConnections = maxRunningConnections #hold on to this for invariant
        self._socketCount = 0 #validation count for full pool. If we ever get to full and have a socket count less than the max pool size, something's wrong
        self._connectTimeOut = connectTimeOut
        self._sslContext = sslContext

    @locked(lock)
    def _reapStaleConnections(self):
        #Check to see if there's anything I can reap
        reaptime = time.time()
        prelen = len(self._pool)
        for addr, t, s in self._pool:
            if t + self._poolTimeOut < reaptime:
                #print 'Reaping close ' + addr
                try:
                    s.close()
                except Exception:
                    #don't care
                    pass
        self._pool = [[a,t,s] for a, t, s in self._pool if t + self._poolTimeOut >= reaptime]
        self._socketCount -= prelen - len(self._pool)
        self._invariant()

    @synchronized(lock)
    def _getConnection(self, addr):
        if len(self._pool) == self._maxSavedConnections:
            #if we're full, clean up
            self._reapStaleConnections()
        sock = None
        socks = [[s,t] for a, t, s in self._pool if a == addr]
        if len(socks) > 0:
            #see if we can find a connection in the pool
            latesttime = sorted([t for s, t in socks])[len(socks)-1]
            sock = [s for s,t in socks if t == latesttime][0]
            self._pool = [[a,t,s] for a, t, s in self._pool if s != sock]
        else:
            #couldn't find one in the pool, so make a new one.
            sockRaw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sockRaw.settimeout(self._connectTimeOut)
            sockRaw.connect((addr, self._port))
            if self._sslContext is not None:
                # Wrap the socket and apply SSLContext to it. This can
                # throw a variation of ssl.SSLError exception especially
                # if there is a problem with the server's certificate.
                sock = self._sslContext.wrap_socket(sockRaw, server_hostname=addr)
            else:
                sock = sockRaw
            
            self._socketCount+=1
        return sock

    @locked(lock)
    def _invariant(self):
        if len(self._pool) > self._maxSavedConnections:
            raise RuntimeError( 'Too many connections in connection pool')
        if self._socketCount > self._maxRunningConnections + self._maxSavedConnections:
            raise RuntimeError('Too many open connections')

    @synchronized(lock)
    def _releaseConnection(self, sock, addr, close):
        if len(self._pool) >= self._maxSavedConnections or close:
            #we're full or we're told to close, so close and don't save
            #print 'Socket close: ' + addr
            sock.close()
            self._socketCount-=1
        else:
            # we have room, so store
            self._pool.append([addr, time.time(), sock])
        self._invariant()
        
    @synchronized(lock)
    def close(self):
        """Close all sockets in the pool and empty it."""
        for addr, t, s in self._pool:
            s.close()
        self._pool = []

    def getConnection(self, addr, timeout=60):
        """Get a socket. 
        
        This will return one from the saved pool if a socket
        for addr exists there.
        
        This method will block waiting for a connection if there are more
        than maxRunningConnections already in use by clients.
        
        @addr is a host name or IP Address to connect to.
        @timeout is an optional timeout (in seconds) for all non-connect operations (see Python socket docs for details)
        @return An open socket
        """
        self._semaphore.acquire()
        #print 'Connectionpool Get ' + addr
        try:
            sock = self._getConnection(addr)
            
            if sock:
                sock.settimeout(timeout)    # set this timeout after it's connected so we don't interfere with that setting
                
            return sock
        except:
            #if something bad happened in getting the connection, release one
            self._semaphore.release()
            raise

    def releaseConnection(self, sock, addr, close):
        """Return a connection to saved pool. 
        
        Optionally close and don't store.
        
        @sock is the socket to return.
        @addr is the host name or IP Address for the socket being returned.
        @close If True, close the socket and don't store it.
        """
        self._semaphore.release()
        self._releaseConnection(sock, addr, close)
        #print 'ConnectionPool Release ' + addr + ' ' + str(close)
    
    @synchronized(lock)
    def storedConnectionCount(self):
        """Get the count of connections in the saved pool."""
        return len(self._pool)
    
