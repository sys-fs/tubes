tubes
=====

tubes is a small program that provides an interface to irc bots that follows
the UNIX philosophy. Messages to and from the server are exposed in FIFO
buffers in /tmp named for the server and appended with either .in or .out:
the server writes to in and the bot writes to out.

Installing
==========

tubes' defaults are configured within tubes.c by changing the values of the
server and port variables at compile time. OpenSSL is a dependency of tubes;
download the devel package from your distro.

To install, cd into the cloned directory and `sudo make install`. Some
tweaking of the Makefile may be necessary, e.g. the location of local manpages.

Custom compiler flags can be appended to the defaults by passing a variable to
make, e.g. `CFLAGS=-fPIC`.
