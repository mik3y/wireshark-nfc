# About #

**wireshark-nfc** is a plugin that allows you to dissect and analyze NFC activity using [Wireshark](http://www.wireshark.org/).  By using the LLCP libpcap file format (see below), your device or driver can generate traces in a common format for later offline analysis.

**Note:** Please join the [wireshark-nfc discussion group](https://groups.google.com/forum/#!forum/wireshark-nfc) if you would like help or have feedback.

![http://wiki.wireshark-nfc.googlecode.com/git/screenshots/wireshark-nfc-main.png](http://wiki.wireshark-nfc.googlecode.com/git/screenshots/wireshark-nfc-main.png)

Currently supported:
  * LLCP 1.1
  * SNEP 1.0
  * NDEF 1.0

# Wireshark Support #

To use the NFC plugins with Wireshark, you need a version of Wireshark that understands the LLCP libpcap format.  This support was checked in to Wireshark in [SVN revision 41368](http://anonsvn.wireshark.org/viewvc?view=revision&revision=41368).

You will need to build Wireshark from source until there is a new Wireshark release including this change.

# Capturing Traces #

Before you can examine activity with wireshark-nfc, you need to have a trace file.  The file format is described below, in _"LLCP libpcap File Format"_.

# Building the Plugin #

```
$ cd plugin/
$ make install
...

$ wireshark examples/android-beam-send.pcap
```

The plugin will be copied to `$HOME/.wireshark/plugins`.

If building against Wireshark sources, point to them by setting `WIRESHARK_INCLUDE` and `WIRESHARK_LIB` in your environment:
```
$ WIRESHARK_INCLUDE=$HOME/svn/wireshark/include \
   WIRESHARK_LIB=$HOME/svn/wireshark/lib \
   make install
```

# LLCP libpcap File Format #

You should store and analyze LLCP traces using the [Libpcap File Format](http://wiki.wireshark.org/Development/LibpcapFileFormat).

pcap capture files always start with the pcap global header.  The `network` field in the this header must be set to `245 (LINKTYPE_NFC_LLCP)`, which is the [registered link type](http://www.tcpdump.org/linktypes.html) for LLCP traces.

The sequence of captured frames follows the global header. For LLCP, each frame consists of a [two-byte LLCP psuedo-header](http://www.tcpdump.org/linktypes/LINKTYPE_NFC_LLCP.html), followed by the actual LLCP data:
```
+---------------------------+
|       Adapter Number      |
|         (1 Octet)         |
+---------------------------+
|           Flags           |
|         (1 Octet)         |
+---------------------------+
|           Payload         |
.                           .
.                           .
.                           .
```

The adapter number field identifies the interface on which the frame was recorded. In most cases this should be set to `0`, but other values may be used, if the capture file contains traces from multiple adapters.

The bits in the flags field are:
  * 0x01 - Direction (0=RX, 1=TX)
  * 0x02-0x80 - Reserved

nfc-wireshark includes a simple python module in `tools/pcap.py`, with methods to construct LLCP pcap dump files.

# Support and Contributing #

For bugs or other ideas, please [file a bug](http://code.google.com/p/wireshark-nfc/issues/list).