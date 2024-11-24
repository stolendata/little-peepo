#!/usr/bin/perl

# little peepo v0.4 - https://github.com/stolendata/little-peepo
#
# (c) 2009 robin leffmann <djinn at stolendata dot net>
#
#   * crude and simplistic POP3 server
#   * speaks only implicit TLS (POP3S), no STARTTLS or unencrypted chatter
#   * can only interact with Maildir, not mbox
#   * understands APOP and USER/PASS auth but not SASL
#   * is your fren and tries hard but may still fail
#
# licensed under CC BY-SA 4.0 - https://creativecommons.org/licenses/by-sa/4.0/

use strict;
use warnings;

use Digest::MD5 'md5_base64';
use Digest::SHA 'sha256_base64';
use IO::Select;
use IO::Socket::IP;
use IO::Socket::SSL;
use POSIX ':sys_wait_h';

use constant DEBUG=>1;
use constant MAX_CLIENTS=>20;
use constant AUTH_GRACE_SEC=>5;
use constant CLIENT_TIMEOUT_SEC=>10;
use constant ERRS_BEFORE_KICK=>10;
use constant EMPTY_TRASH=>1;
use constant SSL_TLS_VERSIONS=>'!SSLv23:!SSLv2:!SSLv3:!TLSv1:!TLSv11';
use constant LISTEN_IP4=>'0.0.0.0';
use constant LISTEN_PORT4=>995;
use constant LISTEN_IP6=>'::';
use constant LISTEN_PORT6=>995;
use constant ACCOUNTS_FILE=>'./peepos.conf'; # here be POP3 accounts/passwords
use constant CERTS_FILE=>'./domains_certs.conf'; # and here be domain/cert map
use constant MAILDIR=>'/var/mail/{U}'; # {U} expands to account's local user

my ( $master, $peepos, $certs ) = ( $$, undef, undef );
my ( $reload, $clients, $errs ) = ( 1, 0, 0 );
my ( $c, $sock4, $sock6 );

$SIG{HUP} = sub { $reload = 1; };
$SIG{CHLD} = sub { $clients-- while waitpid( -1, WNOHANG ) > 0; };

my $sel = IO::Select->new;

for ( [LISTEN_IP4, LISTEN_PORT4, AF_INET, \$sock4, 'IPv4'],
      [LISTEN_IP6, LISTEN_PORT6, AF_INET6, \$sock6, 'IPv6'] )
{
    next unless length $_->[0];

    ${$_->[3]} = IO::Socket::IP->new( Proto=>'tcp', ReuseAddr=>1, ReusePort=>1,
                                      Listen=>MAX_CLIENTS, LocalAddr=>$_->[0],
                                      LocalPort=>$_->[1], Family=>$_->[2] );

    if ( ${$_->[3]} )
    {
        $sel->add( ${$_->[3]} );
        blog( "little peepo is accepting $_->[4] on port $_->[1]" );
    }
}

PARENT: while ( 1 )
{
    if ( $reload )
    {
        $reload = 0;
        $peepos = do ACCOUNTS_FILE;
        $certs = do CERTS_FILE;
        my ( $domains, $accounts ) = ( scalar keys %$certs, 0 );
        $accounts += scalar keys %{$peepos->{$_}} for keys %$certs;
        die 'no domains/accounts configured' if ( !$domains or !$accounts );
        blog( "serving $accounts accounts in $domains domains" );
    }

    my @rdy = $sel->can_read;

    for my $s ( @rdy )
    {
        next unless ( $s == $sock4 or $s == $sock6 );

        undef $c;
        $c = $sock4->accept if $s == $sock4;
        $c = $sock6->accept if $s == $sock6;

        if ( $c )
        {
            if ( $clients >= MAX_CLIENTS )
            {
                $c->shutdown( IO::Socket::SHUT_RDWR );
                blog( $c->peerhost . " denied to connect since we're full" );
                next;
            }

            my $pid = fork or last PARENT;
            $clients++;
            blog( 'connection from ' . $c->peerhost . " forked to pid $pid" );
        }
    }
}

IO::Socket::SSL->start_SSL( $c, Timeout=>5, SSL_server=>1,
                            SSL_version=>SSL_TLS_VERSIONS,
                            SSL_cert_file=>$certs );

if ( $SSL_ERROR )
{
    $c->shutdown( IO::Socket::SHUT_RDWR );
    blog( "disconnecting because $SSL_ERROR" );
    exit;
}

my ( $conn_start, $txphase, $maildir, %maildrop ) = ( time, 0, undef, () );
my ( $account, $user, $cmd_count, @dele ) = ( undef, undef, 0, () );

# APOP auth banner
srand();
my $domain = $c->get_servername;
my $banner = '<';
$banner .= ( 'a'..'z', 'A'..'Z' )[rand(52)] for 1..10;
$banner .= "$$." . substr( $conn_start, 0, -2 ) . "\@$domain>";

blog( $c->peerhost . " connected to $domain with " . $c->get_sslversion );
ok( "little peepo is ready $banner" );

while ( $c->connected )
{
    if ( ($txphase == 0 and time - $conn_start >= AUTH_GRACE_SEC)
         or $errs >= ERRS_BEFORE_KICK )
    {
        blog( 'kicking uncooperative client' );
        last;
    }

    my $buf;
    eval
    {
        local $SIG{ALRM} = sub { die "timed out\n" };
        alarm CLIENT_TIMEOUT_SEC;
        $buf = $c->readline;
        alarm 0;
    };

    # client stalled or connection dropped
    if ( $@ or !length $buf )
    {
        blog( "DEBUG connection hiccup, $!" ) if ( DEBUG and $! );
        blog( "dropped after sending $cmd_count commands" ) unless $@;
        blog( "timed out after sending $cmd_count commands" ) if $@;
        err( 'taking too long' ) if $@;

        last;
    }

    # auth phase

    $buf =~ tr/a-zA-Z0-9 @._-//cd;
    $buf =~ s/^\s+|\s+$//g;
    my @p = split( /\s+/, $buf );
    my $cmd = uc ( $p[0] // '' );
    my $num = length $p[1] ? ( $p[1] =~ tr/0-9//cdr || 0 ) : ''; # hazy...
    my $opt = length $p[2] ? ( $p[2] =~ tr/0-9//cdr || 0 ) : '';

    $buf = 'PASS *' if $cmd eq 'PASS';
    blog( "DEBUG \"$buf\"" ) if DEBUG;

    $cmd_count++ if length $cmd;

    if ( $cmd eq 'QUIT' )
    {
        blog( "quit after sending $cmd_count commands" );
        ok( 'bye' );
        last;
    }
    elsif ( $cmd eq 'CAPA' )
    {
        ok( 'little peepo spellbook' );
        $c->print( "$_\r\n" ) for ( 'IMPLEMENTATION little-peepo-v0.4',
                                    'LOGIN-DELAY 120', 'EXPIRE 0',
                                    'USER', 'UIDL', 'TOP', '.' );
    }
    elsif ( $txphase == 0 )
    {
        if ( $cmd eq 'APOP' and length $p[1] and length $p[2] )
        {
            my $hash = '';
            if ( defined $peepos->{$domain}{$p[1]}
                 and $peepos->{$domain}{$p[1]}[0] =~ /^apop:(.{15,})/ )
            {
                $hash = md5_hex( $banner . $1 );
            }

            if ( $p[2] eq $hash )
            {
                $account = $p[1];
                $user = $peepos->{$domain}{$account}[1];
                $txphase = 1;
            }
            else
            {
                err( 'nope' );
            }
        }
        elsif ( $cmd eq 'USER' and length $p[1] )
        {
            $account = $p[1];
            ok( 'go on' );
        }
        elsif ( $cmd eq 'PASS' and length $p[1] >= 15 and length $account )
        {
            my $hash = sha256_base64( $account . $p[1] );
            $hash .= '=' while ( length $hash ) % 4;

            if ( defined $peepos->{$domain}{$account}
                 and "pass:$hash" eq $peepos->{$domain}{$account}[0] )
            {
                $user = $peepos->{$domain}{$account}[1];
                $txphase = 1;
            }
            else
            {
                err( 'nope' );
                $account = '';
            }
        }
        else
        {
            err( 'uhh' );
        }

        # credentials matched
        if ( $txphase )
        {
            $maildir = MAILDIR =~ s/\{U\}/$user/gr;
            my ( $uid, $gid ) = ( getpwnam($user) )[2, 3];

            my $j = ( $uid // 0 ) ? chroot( $maildir ) : 0;
            $j = chdir( '/' ) if ( $j and $uid and $gid );

            if ( $j )
            {
                $( = $gid; $) = $gid; $< = $uid; $> = $uid;
                $( = $gid; $) = $gid; $< = $uid; $> = $uid;
            }

            # jailing and/or privilege drop failed
            if ( $! or !$j or $> != $uid or ($) =~ /^(\d+)/)[0] != $gid )
            {
                blog( "maildrop $maildir for $account inaccessible" );
                err( 'maildrop not found' );
                last;
            }

            blog( "DEBUG chrooted with privs $uid:$gid" ) if DEBUG;
            tally_maildrop( \%maildrop );
            blog( "$account authenticated for maildrop $maildir" );
            blog( "found $maildrop{count} messages for $account" );

            ok( 'little peepo welcomes you' );
        }
    }
    #
    # transaction phase
    #
    elsif ( $cmd eq 'STAT' or $cmd eq 'RSET' )
    {
        @dele = () if $cmd eq 'RSET';
        delete $maildrop{dele} if $cmd eq 'RSET';

        ok( ($maildrop{count} - scalar @dele) . " $maildrop{bytes}" );
    }
    elsif ( $cmd eq 'LIST' or $cmd eq 'UIDL' )
    {
        my $visible = $maildrop{count} - scalar @dele;
        my $field = $cmd eq 'LIST' ? 'bytes' : 'uid';

        if ( length $p[1] )
        {
            err( 'not found' ), next if !defined $maildrop{msgs}{$num};
            err( 'not found' ), next if defined $maildrop{dele}{$num};
            ok( "$num $maildrop{msgs}{$num}{$field}" );
        }
        else
        {
            ok( "$visible messages" );
            for ( 1..$maildrop{count} )
            {
                next if defined $maildrop{dele}{$_};
                $c->print( "$_ $maildrop{msgs}{$_}{$field}\r\n" );
            }
            $c->print( ".\r\n" );
        }
    }
    elsif ( $cmd eq 'TOP' and length $num and length $opt )
    {
        err( 'not found' ), next if !defined $maildrop{msgs}{$num};
        err( 'not found' ), next if defined $maildrop{dele}{$num};

        my $top = 0;
        ok( "only $opt lines" );
        open( my $fh, '<:raw', $maildrop{msgs}{$num}{file} );
        while ( $opt >= 0 and my $line = <$fh> )
        {
            $c->print( $line );
            $top = 1 if $line =~ /^\r?\n$/;
            $opt-- if $top;
        }
        $c->print( "\r\n.\r\n" );
        close( $fh );
    }
    elsif ( $cmd eq 'RETR' and length $p[1] )
    {
        err( 'not found' ), next if !defined $maildrop{msgs}{$num};
        err( 'not found' ), next if defined $maildrop{dele}{$num};

        if ( my $ok = ok("$maildrop{msgs}{$num}{bytes} bytes") )
        {
            my $out;
            open( my $fh, '<:raw', $maildrop{msgs}{$num}{file} );
            $ok = $c->print( $out ) while ( $ok and read($fh, $out, 8192) );
            $c->print( "\r\n.\r\n" );
            close( $fh );

            if ( $ok )
            {
                my $file = $maildrop{msgs}{$num}{file};
                my $seen = "/cur/$maildrop{msgs}{$num}{base}:2,S";
                blog( "RETR $file -> $seen" );
                rename( $file, $seen ) and $maildrop{msgs}{$num}{file} = $seen;
            }
        }
        else
        {
            err( 'cannot access message' );
        }
    }
    elsif ( $cmd eq 'DELE' and length $p[1] )
    {
        err( 'not found' ), next if !defined $maildrop{msgs}{$num};
        err( 'not found' ), next if defined $maildrop{dele}{$num};
        err( 'not yet seen' ), next if $maildrop{msgs}{$num}{file} !~ /:2,S$/;

        $maildrop{dele}{$num} = 1;
        push( @dele, $num );
        blog( "marked $maildrop{msgs}{$num}{file} as trash" );
        ok( 'poof' );
    }
    elsif ( $cmd eq 'NOOP' )
    {
        ok( 'zzz' );
    }
    else
    {
        err( 'not recognized' );
    }
}

for ( @dele )
{
    my $file = $maildrop{msgs}{$_}{file};

    unlink( $file ) and blog( "purged $file" ), next if EMPTY_TRASH;

    my $trashed = "/cur/$maildrop{msgs}{$_}{base}:2,ST";
    rename( $file, $trashed ) and blog( "trashed $file" );
}

$c->close;


sub blog { print time . ( $$ == $master ? ' [master]' : " [$$]" ) . ": @_\n"; }

sub ok { return $c->print( "+OK $_[0]\r\n" ); }

sub err { $errs++; sleep 1; $c->print( "-ERR $_[0]\r\n" ); }

sub tally_maildrop
{
    my ( $maildrop ) = @_;

    undef $maildrop->{msgs};
    $maildrop->{count} = $maildrop->{bytes} = 0;

    for ( glob('/new/* /cur/*') )
    {
        next if ( $_ =~ /:2,[^T]*T[A-Z]*$/ or ! -f -r $_ or !(my $fs = -s _) );

        my ( $base ) = $_ =~/^\/...\/([^:]+)/;
        my $uid = md5_base64( "$user $base" );

        $maildrop->{count}++;
        $maildrop->{bytes} += $fs;
        $maildrop->{msgs}{$maildrop->{count}}{file} = $_;
        $maildrop->{msgs}{$maildrop->{count}}{base} = $base;
        $maildrop->{msgs}{$maildrop->{count}}{uid} = $uid;
        $maildrop->{msgs}{$maildrop->{count}}{bytes} = $fs;
    }
}
