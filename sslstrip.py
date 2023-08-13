#!/usr/bin/env python3

"""sslstrip is a MITM tool that implements Moxie Marlinspike's SSL stripping attacks."""

__author__ = "Moxie Marlinspike"
__email__ = "moxie@thoughtcrime.org"
__license__ = """
Copyright (c) 2004-2009 Moxie Marlinspike <moxie@thoughtcrime.org>
 
This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License as
published by the Free Software Foundation; either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
USA

"""

import argparse
import logging

from twisted.internet import reactor
from twisted.web import http

from sslstrip.CookieCleaner import CookieCleaner
from sslstrip.StrippingProxy import StrippingProxy
from sslstrip.URLMonitor import URLMonitor


class SSLStripConfig:
    VERSION = "2.0"
    DEFAULT_LOGFILE = "sslstrip.log"
    DEFAULT_LOGLEVEL = logging.WARNING
    DEFAULT_LISTEN_PORT = 10000
    DEFAULT_SPOOF_FAVICON = False
    DEFAULT_KILL_SESSIONS = False


def initialize_logger(logFile, logLevel):
    logging.basicConfig(
        level=logLevel, format="%(asctime)s %(message)s", filename=logFile, filemode="w"
    )


def start_reactor(listenPort, spoofFavicon, killSessions):
    URLMonitor.getInstance().setFaviconSpoofing(spoofFavicon)
    CookieCleaner.getInstance().set_enabled(killSessions)
    strippingFactory = http.HTTPFactory(timeout=10)
    strippingFactory.protocol = StrippingProxy
    reactor.listenTCP(int(listenPort), strippingFactory)
    print(f"\nsslstrip {SSLStripConfig.VERSION} by Moxie Marlinspike running...")
    reactor.run()


def main():
    parser = argparse.ArgumentParser(description="sslstrip")
    parser.add_argument(
        "-w",
        "--write",
        default=SSLStripConfig.DEFAULT_LOGFILE,
        help="Specify file to log to (optional).",
    )
    parser.add_argument(
        "-p",
        "--post",
        default=False,
        action="store_true",
        help="Log only SSL POSTs. (default)",
    )
    parser.add_argument(
        "-s",
        "--ssl",
        default=False,
        action="store_true",
        help="Log all SSL traffic to and from server.",
    )
    parser.add_argument(
        "-a",
        "--all",
        default=False,
        action="store_true",
        help="Log all SSL and HTTP traffic to and from server.",
    )
    parser.add_argument(
        "-l",
        "--listen",
        default=SSLStripConfig.DEFAULT_LISTEN_PORT,
        help="Port to listen on.",
    )
    parser.add_argument(
        "-f",
        "--favicon",
        default=SSLStripConfig.DEFAULT_SPOOF_FAVICON,
        action="store_true",
        help="Substitute a lock favicon on secure requests.",
    )
    parser.add_argument(
        "-k",
        "--killsessions",
        default=SSLStripConfig.DEFAULT_KILL_SESSIONS,
        action="store_true",
        help="Kill sessions in progress.",
    )
    args = parser.parse_args()

    initialize_logger(args.write, SSLStripConfig.DEFAULT_LOGLEVEL)
    start_reactor(args.listen, args.favicon, args.killsessions)


if __name__ == "__main__":
    main()
