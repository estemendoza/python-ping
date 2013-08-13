#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    A pure python ping implementation using raw sockets.

    (This is Python 3 port of https://github.com/jedie/python-ping)
    (Tested and working with python 2.7, should work with 2.6+)

    Note that ICMP messages can only be sent from processes running as root
    (in Windows, you must run this script as 'Administrator').

    Derived from ping.c distributed in Linux's netkit. That code is
    copyright (c) 1989 by The Regents of the University of California.
    That code is in turn derived from code written by Mike Muuss of the
    US Army Ballistic Research Laboratory in December, 1983 and
    placed in the public domain. They have my thanks.

    Bugs are naturally mine. I'd be glad to hear about them. There are
    certainly word - size dependencies here.

    Copyright (c) Matthew Dixon Cowles, <http://www.visi.com/~mdc/>.
    Distributable under the terms of the GNU General Public License
    version 2. Provided with no warranties of any sort.

    Original Version from Matthew Dixon Cowles:
      -> ftp://ftp.visi.com/users/mdc/ping.py

    Rewrite by Jens Diemer:
      -> http://www.python-forum.de/post-69122.html#69122

    Rewrite by George Notaras:
      -> http://www.g-loaded.eu/2009/10/30/python-ping/

    Enhancements by Martin Falatic:
      -> http://www.falatic.com/index.php/39/pinging-with-python

    Enhancements and fixes by Georgi Kolev:
      -> http://github.com/jedie/python-ping/

    Bug fix by Andrejs Rozitis:
      -> http://github.com/rozitis/python-ping/

    Revision history
    ~~~~~~~~~~~~~~~~

    June 19, 2013
    --------------
    * Added support for IPv6. Taken from implementation of Lars Strand.

    March 19, 2013
    --------------
    * Fixing bug to prevent divide by 0 during run-time.

    January 26, 2012
    ----------------
    * Fixing BUG #4 - competability with python 2.x [tested with 2.7]
      - Packet data building is different for 2.x and 3.x.
        'cose of the string/bytes difference.
    * Fixing BUG #10 - the multiple resolv issue.
      - When pinging domain names insted of hosts (for exmaple google.com)
        you can get different IP every time you try to resolv it, we should
        resolv the host only once and stick to that IP.
    * Fixing BUGs #3 #10 - Doing hostname resolv only once.
    * Fixing BUG #14 - Removing all 'global' stuff.
        - You should not use globul! Its bad for you...and its not thread safe!
    * Fix - forcing the use of different times on linux/windows for
            more accurate mesurments. (time.time - linux/ time.clock - windows)
    * Adding quiet_ping function - This way we'll be able to use this script
        as external lib.
    * Changing default timeout to 3s. (1second is not enought)
    * Switching data syze to packet size. It's easyer for the user to ignore
        the fact that the packet headr is 8b and the datasize 64 will make
        packet with size 72.

    October 12, 2011
    --------------
    Merged updates from the main project
      -> https://github.com/jedie/python-ping

    September 12, 2011
    --------------
    Bugfixes + cleanup by Jens Diemer
    Tested with Ubuntu + Windows 7

    September 6, 2011
    --------------
    Cleanup by Martin Falatic. Restored lost comments and docs. Improved
    functionality: constant time between pings, internal times consistently
    use milliseconds. Clarified annotations (e.g., in the checksum routine).
    Using unsigned data in IP & ICMP header pack/unpack unless otherwise
    necessary. Signal handling. Ping-style output formatting and stats.

    August 3, 2011
    --------------
    Ported to py3k by Zach Ware. Mostly done by 2to3; also minor changes to
    deal with bytes vs. string changes (no more ord() in checksum() because
    >source_string< is actually bytes, added .encode() to data in
    send_one_ping()).  That's about it.

    March 11, 2010
    --------------
    changes by Samuel Stauffer:
    - replaced time.clock with default_timer which is set to
      time.clock on windows and time.time on other systems.

    November 8, 2009
    ----------------
    Improved compatibility with GNU/Linux systems.

    Fixes by:
     * George Notaras -- http://www.g-loaded.eu
    Reported by:
     * Chris Hallman -- http://cdhallman.blogspot.com

    Changes in this release:
     - Re-use time.time() instead of time.clock(). The 2007 implementation
       worked only under Microsoft Windows. Failed on GNU/Linux.
       time.clock() behaves differently under the two OSes[1].

    [1] http://docs.python.org/library/time.html#time.clock

    May 30, 2007
    ------------
    little rewrite by Jens Diemer:
     -  change socket asterisk import to a normal import
     -  replace time.time() with time.clock()
     -  delete "return None" (or change to "return" only)
     -  in checksum() rename "str" to "source_string"

    December 4, 2000
    ----------------
    Changed the struct.pack() calls to pack the checksum and ID as
    unsigned. My thanks to Jerome Poincheval for the fix.

    November 22, 1997
    -----------------
    Initial hack. Doesn't do much, but rather than try to guess
    what features I (or others) will want in the future, I've only
    put in what I need now.

    December 16, 1997
    -----------------
    For some reason, the checksum bytes are in the wrong order when
    this is run under Solaris 2.X for SPARC but it works right under
    Linux x86. Since I don't know just what's wrong, I'll swap the
    bytes always and then do an htons().

    ===========================================================================
    IP header info from RFC791
      -> http://tools.ietf.org/html/rfc791)

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Version|  IHL  |Type of Service|          Total Length         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Identification        |Flags|      Fragment Offset    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Time to Live |    Protocol   |         Header Checksum       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Source Address                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Destination Address                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    ===========================================================================
    ICMP Echo / Echo Reply Message header info from RFC792
      -> http://tools.ietf.org/html/rfc792

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |     Type      |     Code      |          Checksum             |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |           Identifier          |        Sequence Number        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |     Data ...
        +-+-+-+-+-

    ===========================================================================
    ICMP parameter info:
      -> http://www.iana.org/assignments/icmp-parameters/icmp-parameters.xml

    ===========================================================================
    An example of ping's typical output:

    PING heise.de (193.99.144.80): 56 data bytes
    64 bytes from 193.99.144.80: icmp_seq=0 ttl=240 time=127 ms
    64 bytes from 193.99.144.80: icmp_seq=1 ttl=240 time=127 ms
    64 bytes from 193.99.144.80: icmp_seq=2 ttl=240 time=126 ms
    64 bytes from 193.99.144.80: icmp_seq=3 ttl=240 time=126 ms
    64 bytes from 193.99.144.80: icmp_seq=4 ttl=240 time=127 ms

    ----heise.de PING Statistics----
    5 packets transmitted, 5 packets received, 0.0% packet loss
    round-trip (ms)  min/avg/max/med = 126/127/127/127

    ===========================================================================
"""

#=============================================================================#
import os
import sys
import socket
import struct
import select
import time
import signal
from icmp_messages import ICMP_CONTROL_MESSAGE, ICMPv6_CONTROL_MESSAGE

if sys.platform == "win32":
    # On Windows, the best timer is time.clock()
    default_timer = time.clock
else:
    # On most other platforms the best timer is time.time()
    default_timer = time.time

#=============================================================================#
# ICMP parameters

ICMP_ECHOREPLY = 0          # Echo reply (per RFC792)
ICMP_ECHO = 8               # Echo request (per RFC792)
ICMP_ECHO_IPV6 = 128        # Echo request (per RFC4443)
ICMP_ECHO_IPV6_REPLY = 129  # Echo request (per RFC4443)
ICMP_PORT = 1
ICMP_PORT_IPV6 = 58
ICMP_MAX_RECV = 2048        # Max size of incoming buffer

MAX_SLEEP = 1000

# class MyStats:
    # destIP   = "0.0.0.0"
    # destHost = "0.0.0.0"
    # pktsSent = 0
    # pktsRcvd = 0
    # minTime  = 999999999
    # maxTime  = 0
    # totTime  = 0
    # avrgTime = 0
    # fracLoss = 1.0
#
# myStats = MyStats # NOT Used globally anymore.
#
#


class PingStats:
    destination_ip = "0.0.0.0"
    destination_host = "unknown"
    destination_port = 0
    packets_sent = 0
    packets_received = 0
    min_time = 999999999
    max_time = 0
    total_time = 0
    average_time = 0

#=============================================================================#


def calculate_checksum(source_string):
    """
    A port of the functionality of in_cksum() from ping.c
    Ideally this would act on the string as a series of 16-bit ints (host
    packed), but this works.
    Network data is big-endian, hosts are typically little-endian
    """
    countTo = (int(len(source_string) / 2)) * 2
    my_sum = 0
    count = 0

    # Handle bytes in pairs (decoding as short ints)
    loByte = 0
    hiByte = 0
    while count < countTo:
        if (sys.byteorder == "little"):
            loByte = source_string[count]
            hiByte = source_string[count + 1]
        else:
            loByte = source_string[count + 1]
            hiByte = source_string[count]
        try:     # For Python3
            my_sum = my_sum + (hiByte * 256 + loByte)
        except:  # For Python2
            my_sum = my_sum + (ord(hiByte) * 256 + ord(loByte))
        count += 2

    # Handle last byte if applicable (odd-number of bytes)
    # Endianness should be irrelevant in this case
    if countTo < len(source_string):  # Check for odd length
        loByte = source_string[len(source_string) - 1]
        try:      # For Python3
            my_sum += loByte
        except:   # For Python2
            my_sum += ord(loByte)

    my_sum &= 0xffffffff  # Truncate sum to 32 bits (a variance from ping.c,
                          # which uses signed ints, but overflow is unlikely
                          # in ping)

    my_sum = (my_sum >> 16) + (my_sum & 0xffff)  # Add high 16 and low 16 bits
    my_sum += (my_sum >> 16)                     # Add carry from above, if any
    answer = ~my_sum & 0xffff                    # Invert & truncate to 16 bits
    answer = socket.htons(answer)

    return answer

#=============================================================================#


class Ping(object):
    def __init__(self, destination, timeout=3000, packet_size=64, own_id=None,
                 quiet=False, silent=False, ipv6=False):
        self.stats = PingStats
        # Statistics
        self.stats.destination_ip = "0.0.0.0"
        self.stats.destination_host = destination
        self.stats.destination_port = ICMP_PORT
        self.stats.packets_sent = 0
        self.stats.packets_received = 0
        self.stats.lost_rate = 100.0
        self.stats.min_time = 999999999
        self.stats.max_time = 0
        self.stats.total_time = 0
        self.stats.average_time = 0.0

        # Parameters
        self.ipv6 = ipv6
        self.timeout = timeout
        self.packet_size = packet_size - 8
        self.sequence_number = 0
        self.unknown_host = False

        self.silent = silent

        if own_id is None:
            self.own_id = os.getpid() & 0xFFFF
        else:
            self.own_id = own_id

        # Output Streams
        if quiet:
            devnull = open(os.devnull, 'w')
            self._stdout = devnull
            self._stderr = devnull
        else:
            self._stdout = sys.stdout
            self._stderr = sys.stderr

        # Get IP from hostname
        try:
            if self.ipv6:
                self.stats.destination_port = ICMP_PORT_IPV6
                info = socket.getaddrinfo(self.stats.destination_host, None)[0]
                self.stats.destination_ip = info[4][0]
            else:
                self.stats.destination_ip = \
                            socket.gethostbyname(self.stats.destination_host)
        except socket.error:
            etype, evalue, etb = sys.exc_info()
            self._stderr.write("\nPYTHON PING: Unknown host: %s (%s)\n" %
                               (self.stats.destination_host, evalue.args[1]))
            #sys.exit(2)
            self.unknown_host = True
            return

        # Print opening line
        if not self.silent:
            sys.stdout.write("PYTHON PING %s (%s):  %d bytes of data.\n" %
                             (self.stats.destination_host,
                              self.stats.destination_ip,
                              self.packet_size))

#=============================================================================#
    def do_one(self):
        """
        Returns either the delay (in ms) or None on timeout.
        """
        delay = None

        # One could use UDP here, but it's obscure
        if self.ipv6:
            sock_af = socket.AF_INET6
            sock_type = socket.SOCK_RAW
            sock_protocol = socket.getprotobyname("ipv6-icmp")
        else:
            sock_af = socket.AF_INET
            sock_type = socket.SOCK_RAW
            sock_protocol = socket.getprotobyname("icmp")
        try:
            current_socket = socket.socket(sock_af, sock_type, sock_protocol)
        except socket.error:
            etype, evalue, etb = sys.exc_info()
            self._stderr.write("socket.error: %s\n" % evalue)
            self._stderr.write("Note that ICMP messages can only be send "
                               "from processes running as root.\n")
            sys.exit(3)

        send_time = self.send_one_ping(current_socket)
        #if send_time == None:
        if send_time is None:
            current_socket.close()
            return delay
        self.stats.packets_sent += 1

        receive_time, packet_size, ip_header, icmp_header = \
                                        self.receive_one_ping(current_socket)
        current_socket.close()

        icmp_seq_number = icmp_header["seq_number"]
        icmp_type = icmp_header["type"]
        icmp_code = icmp_header["code"]

        if self.ipv6:
            host_addr = self.stats.destination_host
        else:
            host_addr = self.stats.destination_ip

        if host_addr == self.stats.destination_host:
            from_info = host_addr
        else:
            if self.ipv6:
                from_info = self.stats.destination_host
            else:
                from_info = "%s (%s)" % (self.stats.destination_host,
                                         host_addr)

        if receive_time:
            ip_header_ttl = ip_header["ttl"]

            delay = (receive_time - send_time) * 1000.0

            self._stdout.write(
                "%d bytes from %s: icmp_seq=%d ttl=%d time=%0.3f ms\n" %
                 (packet_size, from_info, icmp_seq_number,
                     ip_header_ttl, delay))

            self.stats.packets_received += 1
            self.stats.total_time += delay
            if self.stats.min_time > delay:
                self.stats.min_time = delay
            if self.stats.max_time < delay:
                self.stats.max_time = delay
        else:
            if self.ipv6:
                imcp_message = ICMPv6_CONTROL_MESSAGE[icmp_type][icmp_code]
            else:
                imcp_message = ICMP_CONTROL_MESSAGE[icmp_type][icmp_code]
            delay = None
            self._stdout.write("From %s: icmp_seq=%d %s\n" %
                    (self.stats.destination_ip, icmp_seq_number, imcp_message))
            #self._stdout.write("Request timed out.\n")

        return delay

#=============================================================================#
    def send_one_ping(self, current_socket):
        """
        Send one ping to the given >destIP<.
        """

        # Header is type (8), code (8), checksum (16), id (16), sequence (16)
        # (numDataBytes - 8) - Remove header size from packet size
        checksum = 0

        # Make a dummy heder with a 0 checksum.
        if self.ipv6:
            header = struct.pack(
                "!BbHHh", ICMP_ECHO_IPV6, 0, checksum,
                self.own_id, self.sequence_number
            )
        else:
            header = struct.pack(
                "!BBHHH", ICMP_ECHO, 0, checksum,
                self.own_id, self.sequence_number
            )

        pad_bytes = []
        start_val = 0x42
        # 'cose of the string/byte changes in python 2/3 we have
        # to build the data differnely for different version
        # or it will make packets with unexpected size.
        if sys.version[:1] == '2':
            byte = struct.calcsize("d")
            data = ((self.packet_size) - byte) * "Q"
            data = struct.pack("d", default_timer()) + data
        else:
            for i in range(start_val, start_val + (self.packet_size)):
                pad_bytes += [(i & 0xff)]  # Keep chars in the 0-255 range
            #data = bytes(pad_bytes)
            data = bytearray(pad_bytes)

        # Calculate the checksum on the data and the dummy header.
        # Checksum is in network order
        checksum = calculate_checksum(header + data)

        # Now that we have the right checksum, we put that in. It's just easier
        # to make up a new header than to stuff it into the dummy.
        if self.ipv6:
            header = struct.pack("!BbHHh", ICMP_ECHO_IPV6, 0, checksum,
                                 self.own_id, self.sequence_number
                                )
        else:
            header = struct.pack("!BBHHH", ICMP_ECHO, 0, checksum,
                                self.own_id, self.sequence_number
                                )

        packet = header + data

        send_time = default_timer()

        try:
            if self.ipv6:
                current_socket.sendto(packet, (self.stats.destination_ip,
                                               self.stats.destination_port,
                                               0, 0))
            else:
                current_socket.sendto(packet, (self.stats.destination_ip,
                                               self.stats.destination_port))
        except socket.error:
            etype, evalue, etb = sys.exc_info()
            self._stderr.write("General failure (%s)\n" % (evalue.args[1]))
            send_time = None

        return send_time

#=============================================================================#
    def receive_one_ping(self, current_socket):
        """
        Receive the ping from the socket. Timeout = in ms
        """
        time_left = self.timeout / 1000.0

        while True:  # Loop while waiting for packet or timeout
            select_start = default_timer()
            what_ready = select.select([current_socket], [], [], time_left)
            select_duration = (default_timer() - select_start)

            time_received = default_timer()

            packet_data, addr = current_socket.recvfrom(ICMP_MAX_RECV)

            if self.ipv6:
                icmp_header_raw = packet_data[0:8]
            else:
                icmp_header_raw = packet_data[20:28]

            icmp_header = self.header2dict(
                names=[
                    "type", "code", "checksum",
                    "packet_id", "seq_number"
                ],
                struct_format="!BBHHH",
                data=icmp_header_raw
            )

            ip_header = None
            # TODO: Still need to work on IPv6 Headers
            if icmp_header["packet_id"] == self.own_id:  # Our packet
                if self.ipv6:
                    ip_header = self.header2dict(
                        names=[
                            "version", "type", "flow_label",
                            "payload_length", "protocol", "ttl",
                            "src_ip", "dest_ip"
                        ],
                        struct_format="!BBHHBBdd",
                        data=packet_data[:24]
                        #    "src_ip_a", "src_ip_b", "dest_ip_a", "dest_ip_b"
                        #],
                        #struct_format="!BBHHBBQQQQ",
                        #data=packet_data[:40]
                    )
#ip_header['src_ip'] = ip_header['src_ip_a'] + ip_header['src_ip_b']
#ip_header['dest_ip'] = ip_header['dest_ip_a'] + ip_header['dest_ip_b']
                else:
                    ip_header = self.header2dict(
                        names=[
                            "version", "type", "length",
                            "id", "flags", "ttl", "protocol",
                            "checksum", "src_ip", "dest_ip"
                        ],
                        struct_format="!BBHHHBBHII",
                        data=packet_data[:20]
                    )

            if what_ready[0] == []:  # Timeout
                return None, 0, ip_header, icmp_header

            if icmp_header["packet_id"] == self.own_id:  # Our packet
                data_size = len(packet_data) - 28
                return time_received, (data_size + 8), ip_header, icmp_header

            time_left = time_left - select_duration
            if time_left <= 0:
                return None, 0, ip_header, icmp_header

#=============================================================================#

    def calculate_packet_loss(self):
        if self.stats.packets_sent:
            lost_count = self.stats.packets_sent - self.stats.packets_received
            self.stats.lost_rate = \
                        float(lost_count) / self.stats.packets_sent * 100.0
        else:
            self.stats.lost_rate = 100.0

    def calculate_packet_average(self):
        if self.stats.packets_received:
            self.stats.average_time = \
                        self.stats.total_time / self.stats.packets_received
        else:
            self.stats.average_time = 0.0

#=============================================================================#

    def print_stats(self):
        if self.silent:
            return
        sys.stdout.write("\n--- %s PYTHON PING statistics ---\n" %
                                                (self.stats.destination_host))

        self.calculate_packet_loss()

        sys.stdout.write(
"%d packets transmitted, %d received, %0.1f%% packet loss, time %dms\n" % (
            self.stats.packets_sent, self.stats.packets_received,
            self.stats.lost_rate, self.stats.total_time
        ))

        if self.stats.packets_received > 0:
            self.calculate_packet_average()
            sys.stdout.write(
                "round-trip (ms)  min/avg/max = %0.3f/%0.3f/%0.3f\n" % (
                    self.stats.min_time, self.stats.average_time,
                    self.stats.max_time))

#=============================================================================#

    def header2dict(self, names, struct_format, data):
        """
        unpack the raw received IP and ICMP header informations to a dict
        """
        unpacked_data = struct.unpack(struct_format, data)
        return dict(list(zip(names, unpacked_data)))

#=============================================================================#

    def signal_handler(self, signum, frame):
        """
        Handle print_exit via signals
        """
        self.calculate_packet_loss()
        self.print_stats()
        #self._stdout.write("\n(Terminated with signal %d)\n" % (signum))
        sys.exit(not self.stats.packets_received)

    def setup_signal_handler(self):
        signal.signal(signal.SIGINT, self.signal_handler)   # Handle Ctrl-C
        if hasattr(signal, "SIGBREAK"):
            # Handle Ctrl-Break e.g. under Windows
            signal.signal(signal.SIGBREAK, self.signal_handler)

#=============================================================================#

    def run(self, count=None, deadline=None):
        """
        send and receive pings in a loop. Stop if count or until deadline.
        """
        self.setup_signal_handler()

        while True:
            if self.unknown_host:
                return self.stats

            delay = self.do_one()

            self.sequence_number += 1
            if count and self.sequence_number >= count:
                break
            if deadline and self.stats.total_time >= deadline:
                break

            #if delay == None:
            if delay is None:
                delay = 0

            # Pause for the remainder of the MAX_SLEEP period (if applicable)
            if (MAX_SLEEP > delay):
                time.sleep((MAX_SLEEP - delay) / 1000.0)

        self.calculate_packet_loss()
        self.print_stats()
        return self.stats

#=============================================================================#


def ping(hostname, count=3, timeout=3000, packet_size=64, own_id=None,
         quiet=False, silent=False, ipv6=False):
    p = Ping(hostname, timeout, packet_size, own_id, quiet, silent, ipv6)
    stats = p.run(count)
    return(not stats.packets_received)

#=============================================================================#


def usage():
    usage_message = "Usage: %s hostname" % (sys.argv[0])
    sys.stderr.write(usage_message)

#=============================================================================#


def run_tests():
    # These should work:
    ping("8.8.8.8")
    ping("heise.de")
    ping("google.com")

    # Inconsistent on Windows w/ ActivePython (Python 3.2 resolves correctly
    # to the local host, but 2.7 tries to resolve to the local *gateway*)
    ping("localhost")

    # Should fail with 'getaddrinfo failed':
    ping("foobar_url.foobar")

    # Should fail (timeout), but it depends on the local network:
    ping("192.168.255.254")

    # Should fails with 'The requested address is not valid in its context':
    ping("0.0.0.0")


#=============================================================================#


def main(arguments):

    # There is some duplication in trying to not break for older versions.
    # OptionParser is still present in current versions, but it is deprecated,
    # in favor of argparse.
    try:
        import argparse

        parser = argparse.ArgumentParser(
            description='Send ICMP ECHO_REQUEST to network hosts')
        parser.add_argument('destination', type=str, nargs='?',
            help='destination')
        parser.add_argument('--test', action="store_true",
            help='Run a basic test suite')
        parser.add_argument('-q', '--quiet', action="store_true",
            help='Quiet output.  Nothing is displayed except the summary '
                 'lines at startup time and when finished.')
        parser.add_argument('--ipv6', action="store_true",
            help='Run using IPv6, instead of the default (IPv4)')
        parser.add_argument('-c', dest='count', metavar='count', type=int,
            default=3, help='Stop after sending count ECHO_REQUEST packets.')
        parser.add_argument('-s', dest='packetsize', metavar='packetsize',
            type=int, default=64,
            help='Specifies the number of data bytes to be sent.  The default '
                 'is 56, which translates into 64 ICMP data bytes when'
                 'combined with the 8 bytes of ICMP header data.')
        parser.add_argument('-W', dest='timeout', metavar='timeout', type=int,
            default=3,
            help='Time to wait for a response, in seconds.')

        args = parser.parse_args()
    except ImportError:
        from optparse import OptionParser

        parser = OptionParser(
            description='Send ICMP ECHO_REQUEST to network hosts')
        parser.add_option('--test', action="store_true",
            help='Run a basic test suite')
        parser.add_option('-q', '--quiet', action="store_true",
            help='Quiet output.  Nothing is displayed except the summary '
                 'lines at startup time and when finished.')
        parser.add_option('--ipv6', action="store_true",
            help='Run using IPv6, instead of the default (IPv4)')
        parser.add_option('-c', dest='count', metavar='count', type=int,
            default=3, help='Stop after sending count ECHO_REQUEST packets.')
        parser.add_option('-s', dest='packetsize', metavar='packetsize',
            type=int, default=64,
            help='Specifies the number of data bytes to be sent.  The default '
                 'is 56, which translates into 64 ICMP data bytes when '
                 'combined with the 8 bytes of ICMP header data.')
        parser.add_option('-W', dest='timeout', metavar='timeout', type=int,
            default=3,
            help='Time to wait for a response, in seconds.')

        (args, positional_args) = parser.parse_args()

        # Add destination to this object to match argparse.parse_args() output
        if positional_args:
            args.destination = positional_args[0]
        else:
            args.destination = False

    if args.test:
        run_tests()
        sys.exit(1)

    if not args.destination:
        parser.print_help()
        sys.exit(1)

    retval = ping(hostname=args.destination,
                  count=args.count,
                  timeout=args.timeout,
                  packet_size=args.packetsize,
                  own_id=None,
                  quiet=args.quiet,
                  ipv6=args.ipv6
                  )
    sys.exit(retval)


#=============================================================================#
if __name__ == '__main__':
    main(sys.argv)
