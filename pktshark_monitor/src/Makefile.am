
bin_PROGRAMS = pktshark_monitor
AM_CFLAGS = -g -Wall -Werror $(LIBNL3_CFLAGS) $(LIBNLG3_CFLAGS) $(READLINE_CFLAGS)
AM_LDFLAGS = $(LIBNL3_LIBS) $(LIBNLG3_LIBS) $(READLINE_LIBS) -lpcap
AM_CPPFLAGS = -D_GNU_SOURCE

pktshark_monitor_SOURCES = main.c 
