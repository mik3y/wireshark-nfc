#!/usr/bin/env python
#
# Copyright 2012 Google Inc.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
# USA.

"""Library for generating libpcap/LLCP capture files."""

__author__ = 'mikey@google.com (mike wakerly)'

import math
import struct
import time

PCAP_MAGIC = 0xa1b2c3d4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4

ENCAP_LLCP = 245

def pcap_global_header(thiszone=0, sigfigs=0, snaplen=65535, network=ENCAP_LLCP):
  """Builds a PCAP global header.

  Standard PCAP header, does not contain anything LLCP-specific.
  """
  header = struct.pack('!IHHiIII', PCAP_MAGIC, PCAP_VERSION_MAJOR,
      PCAP_VERSION_MINOR, thiszone, sigfigs, snaplen, network)
  return header

def pcap_packet_header(when, data):
  """Builds a standard libpcap packet header for `data`."""
  usec, sec = math.modf(when)
  sec = int(sec)
  usec = int(usec * 10e5)
  datalen = len(data)
  header = struct.pack('!IIII', sec, usec, datalen, datalen)
  return header

def write_pcap_packet(fd, data, when=None):
  """Builds the pcap packet header and writes it and `data` to `fd`.

  Protocol-specific (LLCP) per-packet header must already be present in `data`.
  """
  if not when:
    when = time.time()
  header = pcap_packet_header(when, data)
  fd.write(header)
  fd.write(data)
  return fd

def write_pcap_packets(filename, packets):
  fd = open(filename, 'wb')
  fd.write(pcap_global_header())
  for p in packets:
    print repr(p)
    if type(p) == type(''):
      write_pcap_packet(fd, p)
    else:
      write_pcap_packet(fd, p[0], when=p[1])
  fd.close()

def llcp_pcap_packet_header(adapter, sent):
  """Builds and returns the LLCP-specific packet header.

  Contents:
    2-byte adapter number
    2-byte flags:
      LSB: sent (0=false, 1=true)
  """
  flags = [0, 1][sent]
  return struct.pack('!BB', adapter, flags)

def llcp_pcap_packet(sent, dsap, ptype, ssap, seqn=None, info='', adapter=0xde):
  """Builds a raw LLCP packet with given parameters.

  Includes LLCP pcap packet header.
  """
  dsap &= 0x3f
  ssap &= 0x3f

  b0 = ((dsap << 2) | ((ptype >> 2) & 0x3)) & 0xff
  b1 = ((ptype << 6) | ssap) & 0xff

  ret = llcp_pcap_packet_header(adapter, sent)
  ret += struct.pack('BB', b0, b1)
  if seqn is not None:
    ret += struct.pack('B', seqn)
  ret += info
  return ret

def llcp_tx(*args, **kwargs):
  return llcp_pcap_packet(True, *args, **kwargs)

def llcp_rx(*args, **kwargs):
  return llcp_pcap_packet(False, *args, **kwargs)

if __name__ == '__main__':
  import sys
  packets = (
    llcp_tx(dsap=4, ssap=2, ptype=0),
    llcp_rx(dsap=2, ssap=4, ptype=0),
    llcp_tx(dsap=4, ssap=2, ptype=12, seqn=0x11, info='\x10\x01\x00\x00\x00\x02\x0a\x0b'),
    llcp_rx(dsap=2, ssap=4, ptype=12, seqn=0x11),
  )
  write_pcap_packets('llcp.pcap', packets)
