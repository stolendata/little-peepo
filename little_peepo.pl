#!/usr/bin/perl

# little peepo v0.2 - https://github.com/stolendata/little-peepo
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

use Digest::MD5 'md5_hex';
use Digest::SHA 'sha256_base64';
use File::Basename 'basename';
use IO::Select;
use IO::Socket::SSL;
use POSIX ':sys_wait_h';

use constant DEBUG=>1;
use constant MAX_CLIENTS=>5;
use constant AUTH_GRACE_SEC=>5;
use constant CLIENT_TIMEOUT_SEC=>10;
use constant ERRS_BEFORE_KICK=>10;
use constant EMPTY_TRASH=>1;
use constant SSL_TLS_VERSIONS=>'!SSLv23:!SSLv2:!SSLv3:!TLSv1:!TLSv11';
use constant LISTEN_IP=>'0.0.0.0';
use constant LISTEN_PORT=>995;
use constant ACCOUNTS_FILE=>'./peepos.conf'; # here be POP3 accounts/passwords
use constant CERTS_FILE=>'./domains_certs.conf'; # and here be domain/cert map
use constant MAILDIR=>'/var/mail/{U}'; # {U} expands to account's local user

my ( $master, $peepos, $certs ) = ( $$, undef, undef );
my ( $reload, $clients, $errs, $c ) = ( 1, 0, 0, undef );

$SIG{HUP} = sub { $reload = 1; };
$SIG{CHLD} = sub { $clients-- while waitpid( -1, WNOHANG ) > 0; };

my $sel = IO::Select->new;

my $sock = IO::Socket::INET->new( LocalAddr=>LISTEN_IP, LocalPort=>LISTEN_PORT,
                                  Proto=>'tcp', Listen=>MAX_CLIENTS,
                                  ReuseAddr=>1, ReusePort=>1 ) or die $!;

$sel->add( $sock );

blog( 'little peepo is accepting connections on port ' . LISTEN_PORT );

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

    undef $c;
    for my $s ( @rdy )
    {
        next unless $s = $sock;

        $c = $sock->accept;

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
ok( $c, "little peepo is ready $banner" );

while ( $c->connected )
{
    blog( 'kicking noisy client' ), last if $errs >= ERRS_BEFORE_KICK;

    if ( $txphase == 0 and time - $conn_start >= AUTH_GRACE_SEC )
    {
        blog( 'kicking stalling client' );
        last;
    }

    my ( $buf, $rb );
    eval
    {
        local $SIG{ALRM} = sub { die "timed out\n" };
        alarm CLIENT_TIMEOUT_SEC;
        $rb = read( $c, $buf, 128 );
        alarm 0;
    };

    # client stalled or connection dropped
    if ( $@ or !$rb )
    {
        blog( "DEBUG connection hiccup, $!" ) if ( DEBUG and $! );

        blog( "timed out after sending $cmd_count commands" ) if $@;
        err( $c, 'taking too long' ) if $@;

        blog( "dropped after sending $cmd_count commands" ) unless $@;

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
        ok( $c, 'bye' );
        last;
    }
    elsif ( $cmd eq 'CAPA' )
    {
        ok( $c, 'little peepo spellbook' );
        print $c "$_\r\n" for ( 'IMPLEMENTATION little-peepo-v0.2',
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
                err( $c, 'nope' );
            }
        }
        elsif ( $cmd eq 'USER' and length $p[1] )
        {
            $account = $p[1];
            ok( $c, 'go on' );
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
                err( $c, 'nope' );
                $account = '';
            }
        }
        else
        {
            err( $c, 'uhh' );
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
            if ( $! or !$j or $> != $uid or ($) =~ /(^\d+)/)[0] != $gid )
            {
                blog( "maildrop $maildir for $account inaccessible" );
                err( $c, 'maildrop not found' );
                last;
            }

            blog( "DEBUG chrooted with privs $uid:$gid" ) if DEBUG;
            tally_maildrop( \%maildrop );
            blog( "$account authenticated for maildrop $maildir" );
            blog( "found $maildrop{count} messages for $account" );

            ok( $c, 'little peepo welcomes you' );
        }
    }
    #
    # transaction phase
    #
    elsif ( $cmd eq 'STAT' )
    {
        ok( $c, ($maildrop{count} - scalar @dele) . " $maildrop{bytes}" );
    }
    elsif ( $cmd eq 'LIST' or $cmd eq 'UIDL' )
    {
        my $visible = $maildrop{count} - scalar @dele;
        my $field = $cmd eq 'LIST' ? 'bytes' : 'uid';

        if ( length $p[1] )
        {
            err( $c, 'not found' ), next if !defined $maildrop{msgs}{$num};
            err( $c, 'not found' ), next if defined $maildrop{dele}{$num};
            ok( $c, "$num $maildrop{msgs}{$num}{$field}" );
        }
        else
        {
            ok( $c, "$visible messages" );
            for ( 1..$maildrop{count} )
            {
                next if defined $maildrop{dele}{$num};
                print $c "$_ $maildrop{msgs}{$_}{$field}\r\n";
            }
            print $c ".\r\n";
        }
    }
    elsif ( $cmd eq 'TOP' and length $num and length $opt )
    {
        err( $c, 'not found' ), next if !defined $maildrop{msgs}{$num};
        err( $c, 'not found' ), next if defined $maildrop{dele}{$num};

        my $top = 0;
        ok( $c, "only $opt lines" );
        open( my $fh, '<:raw', '/new/' . $maildrop{msgs}{$num}{file} );
        while ( $opt >= 0 and my $line = <$fh> )
        {
            print $c $line;
            $top = 1 if $line =~ /^\r?\n$/;
            $opt-- if $top;
        }
        print $c "\r\n.\r\n";
        close( $fh );
    }
    elsif ( $cmd eq 'RETR' and length $p[1] )
    {
        err( $c, 'not found' ), next if !defined $maildrop{msgs}{$num};
        err( $c, 'not found' ), next if defined $maildrop{dele}{$num};

        if ( my $ok = ok($c, "$maildrop{msgs}{$num}{bytes} bytes") )
        {
            my $out;
            my $file = $maildrop{msgs}{$num}{file};
            open( my $fh, '<:raw', "/new/$file" );
            $ok = print $c $out while ( $ok and read($fh, $out, 8192) );
            print $c "\r\n.\r\n";
            close( $fh );

            if ( $ok )
            {
                my $newfile = $file =~ /:2,$/ ? "${file}S" : "$file:2,S";
                $ok = rename( "/new/$file", "/cur/$newfile" );
                blog( "RETR $file -> $newfile" ) if $ok;
                $maildrop{msgs}{$num}{file} = $newfile if $ok;
            }
        }
        else
        {
            err( $c, 'cannot access message' );
        }
    }
    elsif ( $cmd eq 'DELE' and length $p[1] )
    {
        err( $c, 'not found' ), next if !defined $maildrop{msgs}{$num};
        err( $c, 'not found' ), next if defined $maildrop{dele}{$num};

        my $file = $maildrop{msgs}{$num}{file};
        my $newfile = $file =~ s/(?::2,[^T]?)?$/:2,T/r;
        my $ok = rename( "/cur/$file", "/cur/$newfile" );

        push( @dele, $newfile ) if $ok;
        $maildrop{dele}{$num} = 1 if $ok;
        blog( "DELE $file -> $newfile" ) if $ok;
        ok( $c, 'poof' ) if $ok;
        err( $c, 'cannot access message' ) if !$ok;
    }
    elsif ( $cmd eq 'RSET' )
    {
        @dele = ();
        delete $maildrop{dele};
        ok( $c, 'deletions undone' );
    }
    elsif ( $cmd eq 'NOOP' )
    {
        ok( $c, 'zzz' );
    }
    else
    {
        err( $c, 'not recognized' );
    }
}

if ( EMPTY_TRASH )
{
    unlink "/cur/$_" and blog( "purged $_" ) for @dele;
}

$c->close;


sub blog
{
    my ( $msg ) = @_;

    print time . ' [' . ( $$ == $master ? 'master' : $$ ) . "]: $msg\n";
}

sub ok { my ( $c, $msg ) = @_; return print $c "+OK $msg\r\n"; }

sub err { my ( $c, $msg ) = @_; $errs++; sleep 1; print $c "-ERR $msg\r\n"; }

sub tally_maildrop
{
    my ( $maildrop ) = @_;

    undef $maildrop->{msgs};
    $maildrop->{count} = $maildrop->{bytes} = 0;

    for ( glob('/new/*') )
    {
        next unless ( -f $_ and -r $_ and $_ !~ /:2,[a-z0-9]+$/i
                      and (my $fs = -s $_) );

        my $file = basename( $_ );
        my ( $uid ) = $file =~ /^([^,:]+)/;

        $maildrop->{count}++;
        $maildrop->{bytes} += $fs;
        $maildrop->{msgs}{$maildrop->{count}}{file} = $file;
        $maildrop->{msgs}{$maildrop->{count}}{uid} = md5_hex( $uid );
        $maildrop->{msgs}{$maildrop->{count}}{bytes} = $fs;
    }
}
