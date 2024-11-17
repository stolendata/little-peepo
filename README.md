A crude and simplistic POP3 server
==================================
Copyright © 2009 Robin Leffmann \<djinn \[at\] stolendata.net>

No mbox support. No SASL support. No nothing. Requires [IO::Socket::IP](https://metacpan.org/pod/IO::Socket::IP) and [IO::Socket::SSL](https://metacpan.org/pod/IO::Socket::SSL). Accounts, domains and certificates can be reloaded at run-time by sending SIGHUP. See `little_peepo.pl` for configuration and scant documentation, `domains_certs.conf` for domain and certificate setup, and `peepos.conf` for information on how to create accounts.

License
-------
Licensed under Creative Commons BY-SA 4.0 - https://creativecommons.org/licenses/by-sa/4.0/
