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

"""Utility to scrape LLCP debug messages and output a libpcap stream."""

__author__ = 'mikey@google.com (mike wakerly)'

import pcap
import re
import sys
import time

LOGCAT_RE = re.compile('.*/LLCP.+[<>].+\[([0-9a-fA-F]*)\]?$')

def to_bytes(chars):
  numbytes = len(chars) / 2
  res = ''
  for i in xrange(numbytes):
    res += chr(int(chars[i*2:(i+1)*2], 16))
  return res

def main():
  infd = sys.stdin
  outfd = sys.stdout

  outfd.write(pcap.pcap_global_header())
  outfd.flush()

  while True:
    line = infd.readline().strip()
    m = LOGCAT_RE.match(line)
    if m:
      chars = m.group(1)
      sys.stderr.write('%s\n' % chars)
      sent = '>' in line

      hdr = pcap.llcp_pcap_packet_header(0, sent)
      data = hdr + to_bytes(chars)

      outfd.write(pcap.pcap_packet_header(time.time(), data))
      outfd.write(data)
      outfd.flush()

if __name__ == '__main__':
  main()
