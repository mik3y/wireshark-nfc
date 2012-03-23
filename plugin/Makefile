# Makefile for plugin.

CC = gcc

SRCS = \
	packet-llcp.c \
	packet-snep.c \
	packet-ndef.c \
	plugin.c

OBJS = $(foreach src, $(SRCS), $(src:.c=.o))

PLUGIN = nfc-wireshark.so

OUT_PLUGINS = $(HOME)/.wireshark/plugins

WIRESHARK_INCLUDE ?= /usr/local/wireshark
WIRESHARK_LIB ?= /usr/lib/wireshark

CFLAGS := \
	-g \
	-DWS_VAR_IMPORT=extern \
	-DHAVE_CONFIG_H \
	-DHAVE_STDARG_H \
	-DHAVE_VPRINTF \
	-fPIC \
	-I$(WIRESHARK_INCLUDE) \
	 $(shell pkg-config --cflags gmodule-2.0) \
	 $(CFLAGS)

CXXFLAGS = $(CFLAGS)

LDFLAGS := \
	-g \
	-L$(WIRESHARK_LIB) \
	-lwireshark \
	-shared \
	-dynamiclib \
	-fPIC

OBJS = $(SRCS:.c=.o)

all: $(PLUGIN)

install: $(PLUGIN)
	mkdir -p $(OUT_PLUGINS)
	cp -f $< $(OUT_PLUGINS)

$(PLUGIN): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

clean:
	rm -f $(OBJS) $(PLUGIN)

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

.PHONY: all clean install
