#!/usr/bin/env python
#
# Copyright 2012 Google Inc and Sony Corp.
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

"""Converts nfcpy log traces to a wireshark-compatible pcap trace."""

__author__ = 'frank.dawidowsky@eu.sony.com'

import pcap
import csv
import re
import sys

def main():
  if len(sys.argv) < 2 or len(sys.argv) > 3:
    helpPage()
    return

  inFile = sys.argv[1]
  outFile = sys.argv[2]

  timestamp = 0
  outfd = open(outFile, 'wb')
  outfd.write(pcap.pcap_global_header())
  outfd.flush()

  infd = open(inFile, "rb")
  f = infd.readlines()
  for line in f:
    try:
      p = line.index("dep raw")
      role = ">>" in line;
      payload = line[p+11:].rstrip()
      hdr = pcap.llcp_pcap_packet_header(0, role)
      data = hdr + payload.decode("hex")
      outfd.write(pcap.pcap_packet_header(timestamp, data))
      outfd.write(data)
      outfd.flush()
    except ValueError: # happens when reading header
      pass

def helpPage():
  print "###############################################################"
  print "###  nfcpy2pcap converter                                   ###"
  print "###  converts nfcpy traces created with -d nfc.dep          ###"
  print "###  to pcap format so data can be imported into wireshark  ###"
  print "###                                                         ###"
  print "### usage:                                                  ###"
  print "### nfcpy2pcap input.log output.pcap                        ###"
  print "###############################################################"

if __name__ == '__main__':
  main()
