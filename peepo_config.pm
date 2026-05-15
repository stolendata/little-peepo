package main;

# enables additional log output
use constant DEBUG=>1;

# maximum number of simultaneous clients
use constant MAX_CLIENTS=>20;

# clients that haven't authenticated in this many seconds will be kicked
use constant AUTH_GRACE_SEC=>5;

# clients sending no commands will be kicked after idling this many seconds
use constant CLIENT_TIMEOUT_SEC=>10;

# clients that just "poke around" will be kicked after this many errors
use constant ERRS_BEFORE_KICK=>10;

# delete trashed e-mail after the client has disconnected
use constant EMPTY_TRASH=>1;

# permissible TLS versions (see OpenSSL's "ssl_protocols" parameter)
use constant SSL_TLS_VERSIONS=>'TLSv13';

# setting LISTEN_IP4 to an empty string disables IPv4 connectivity
use constant LISTEN_IP4=>'0.0.0.0';
use constant LISTEN_PORT4=>995;

# setting LISTEN_IP6 to an empty string disables IPv6 connectivity
use constant LISTEN_IP6=>'::';
use constant LISTEN_PORT6=>995;

# path to your system's Maildir - {U} expands to the account's local user
use constant MAILDIR=>'/var/mail/{U}';

# here be POP3 accounts and passwords
use constant ACCOUNTS_FILE=>'/etc/little_peepo/peepos.conf';

# here be domain-and-certificate map
use constant CERTS_FILE=>'/etc/little_peepo/domains_certs.conf';

use constant LOG_FILE=>'/var/log/little_peepo.log';

1;
