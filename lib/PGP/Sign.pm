# Create a PGP signature for data, securely.
#
# THIS IS NOT A GENERAL PGP MODULE.
#
# For a general PGP module that handles encryption and decryption, key ring
# management, and all of the other wonderful things you want to do with PGP,
# see the PGP module directory on CPAN.  This module is designed to do one and
# only one thing and do it fast, well, and securely -- create and check
# detached signatures for some block of data.
#
# This above all: to thine own self be true,
# And it must follow, as the night the day,
# Thou canst not then be false to any man.
#                               -- William Shakespeare, _Hamlet_
#
# SPDX-License-Identifier: GPL-1.0-or-later OR Artistic-1.0-Perl

##############################################################################
# Modules and declarations
##############################################################################

package PGP::Sign;
require 5.003;

use Carp qw(croak);
use Exporter ();
use Fcntl qw(F_SETFD O_WRONLY O_CREAT O_EXCL);
use FileHandle ();
use IPC::Open3 qw(open3);

use strict;
use vars qw(@ERROR @EXPORT @EXPORT_OK @ISA $MUNGE $PGPS $PGPV $PGPPATH
            $PGPSTYLE $TMPDIR $VERSION);

@ISA       = qw(Exporter);
@EXPORT    = qw(pgp_sign pgp_verify);
@EXPORT_OK = qw(pgp_error);

# The current PGP::Sign version number.
$VERSION = '0.20';

##############################################################################
# Global variables
##############################################################################

# The text of any errors resulting from the last call to pgp_sign().
@ERROR = ();

# Whether or not to perform some standard munging to make other signing and
# checking routines happy.
$MUNGE = 0;

# The default path to PGP.  PGPS is for signing, PGPV is for verifying (with
# PGP v5 these are two different commands).
$PGPS = '/usr/bin/gpg1';
$PGPV = '/usr/bin/gpg1';

# The path to the directory containing the key ring.  If not set, defaults to
# $ENV{GNUPGHOME} or $HOME/.gnupg.
$PGPPATH = '';

# What style of PGP invocation to use by default.  The only allowable value is
# GPG.
$PGPSTYLE = 'GPG';

# The directory in which temporary files should be created.
$TMPDIR = $ENV{TMPDIR} || '/tmp';

##############################################################################
# Implementation
##############################################################################

# This function actually sends the data to a file handle.  It's necessary to
# implement munging (stripping trailing spaces on a line).
{
    my $spaces = '';
    sub output {
        my ($fh, $string) = @_;
        if ($MUNGE) {
            $string = $spaces . $string;
            $string =~ s/ +(\n.)/$1/g;
            my $newline = ($string =~ s/\n$//);
            $string =~ s/( +)$//;
            if ($newline) { $string .= "\n" } else { $spaces = $1 }
        } else {
            $spaces = '';
        }
        print $fh $string;
    }
}

# This is our generic "take this data and shove it" routine, used both for
# signature generation and signature checking.  The first argument is the file
# handle to shove all the data into, and the remaining arguments are sources
# of data.  Scalars, references to arrays, references to FileHandle or
# IO::Handle objects, file globs, references to code, and references to file
# globs are all supported as ways to get the data, and at most one line at a
# time is read (cutting down on memory usage).
#
# References to code are an interesting subcase.  A code reference is executed
# repeatedly, whatever it returns being passed to PGP using the ORS specified
# if any, until it returns undef.
sub write_data {
    my $fh = shift;

    # Deal with all of our possible sources of input, one at a time.  We
    # really want perl 5.004 here, since we want UNIVERSAL::isa().
    # Unfortunately, we can't rely on 5.004 yet.  *But*, the main reason we
    # want isa() is to handle the various derived IO::Handle classes, and
    # 5.003 should only have FileHandle, so we can hack our way around that.
    # We can't do anything interesting or particularly "cool" with references
    # to references, so those we just print.  (Perl allows circular
    # references, so we can't just dereference references to references until
    # we get something interesting.)  Hashes are treated like arrays.
    my $source;
    for $source (@_) {
        if (ref $source eq 'ARRAY' or ref $source eq 'HASH') {
            for (@$source) { output ($fh, $_) }
        } elsif (ref $source eq 'GLOB' or ref \$source eq 'GLOB') {
            local $_;
            while (<$source>) { output ($fh, $_) }
        } elsif (ref $source eq 'SCALAR') {
            output ($fh, $$source);
        } elsif (ref $source eq 'CODE') {
            local $_;
            while (defined ($_ = &$source ())) { output ($fh, $_) }
        } elsif (ref $source eq 'REF') {
            output ($fh, $source);
        } elsif (ref $source)  {
            if ($] > 5.003) {
                if (UNIVERSAL::isa ($source, 'IO::Handle')) {
                    local $_;
                    while (<$source>) { output ($fh, $_) }
                } else {
                    output ($fh, $source);
                }
            } else {
                if (ref $source eq 'FileHandle') {
                    local $_;
                    while (<$source>) { output ($fh, $_) }
                } else {
                    output ($fh, $source);
                }
            }
        } else {
            output ($fh, $source);
        }
    }
}

# Create a detached signature for the given data.  The first argument should
# be a key id and the second argument the PGP passphrase, and then all
# remaining arguments are considered to be part of the data to be signed and
# are handed off to write_data().
#
# In a scalar context, the signature is returned as an ASCII-armored block
# with embedded newlines.  In array context, a list consisting of the
# signature and the PGP version number is returned.  Returns undef in the
# event of an error, and the error text is then stored in @PGP::Sign::ERROR
# and can be retrieved with pgp_error().
sub pgp_sign {
    my $keyid = shift;
    my $passphrase = shift;

    # Ignore SIGPIPE, since we're going to be talking to PGP.
    local $SIG{PIPE} = 'IGNORE';

    # Figure out what command line we'll be using.
    if ($PGPSTYLE ne 'GPG') {
        croak("Unknown \$PGPSTYLE setting $PGPSTYLE");
    }
    my @command = ($PGPS, '--detach-sign', '--armor', '--textmode',
                   '--batch', '--force-v3-sigs', '-u', $keyid);

    # We need to send the password to PGP, but we don't want to use either the
    # command line or an environment variable, since both may expose us to
    # snoopers on the system.  So we create a pipe, stick the password in it,
    # and then pass the file descriptor to GnuPG.  5.005_03 started setting
    # close-on-exec on file handles > $^F, so we need to clear that here (but
    # ignore errors on platforms where fcntl or F_SETFD doesn't exist, if
    # any).
    my $passfh = new FileHandle;
    my $writefh = new FileHandle;
    pipe ($passfh, $writefh);
    eval { fcntl ($passfh, F_SETFD, 0) };
    print $writefh $passphrase;
    close $writefh;
    local $ENV{PGPPASSFD};
    push (@command, '--passphrase-fd', $passfh->fileno);

    # Fork off a pgp process that we're going to be feeding data to, and tell
    # it to just generate a signature using the given key id and pass phrase.
    # Set PGPPATH if desired.
    if ($PGPPATH) {
        push (@command, '--homedir', $PGPPATH);
    }
    my $pgp = new FileHandle;
    my $signature = new FileHandle;
    my $errors = new FileHandle;
    my $pid = eval { open3 ($pgp, $signature, $errors, @command) };
    if ($@) {
        @ERROR = ($@, "Execution of $command[0] failed.\n");
        return undef;
    }

    # Send the rest of the arguments off to write_data().
    unshift (@_, $pgp);
    &write_data;

    # All done.  Close the pipe to PGP, clean up, and see if we succeeded.  If
    # not, save the error output and return undef.
    close $pgp;
    local $/ = "\n";
    my @errors = <$errors>;
    my @signature = <$signature>;
    close $signature;
    close $errors;
    close $passfh;
    waitpid ($pid, 0);
    if ($? != 0) {
        @ERROR = (@errors, "$command[0] returned exit status $?\n");
        return undef;
    }

    # Now, clean up the returned signature and return it, along with the
    # version number if desired.
    while ((shift @signature) !~ /-----BEGIN PGP SIGNATURE-----\n/) {
        unless (@signature) {
            @ERROR = ("No signature from PGP (command not found?)\n");
            return undef;
        }
    }
    my $version;
    while ($signature[0] ne "\n" && @signature) {
        $version = $1 if ((shift @signature) =~ /^Version:\s+(.*?)\s*$/);
    }
    shift @signature;
    pop @signature;
    $signature = join ('', @signature);
    chomp $signature;
    undef @ERROR;
    wantarray ? ($signature, $version) : $signature;
}

# Check a detatched signature for given data.  Takes a signature block (in the
# form of an ASCII-armored string with embedded newlines), a version number
# (which may be undef), and some number of data sources that write_data() can
# handle and returns the key id of the signature, the empty string if the
# signature didn't check, and undef in the event of an error.  In the event of
# some sort of an error, we stick the error in @ERROR.
sub pgp_verify {
    my $signature = shift;
    my $version = shift;
    chomp $signature;

    # Ignore SIGPIPE, since we're going to be talking to PGP.
    local $SIG{PIPE} = 'IGNORE';

    # Because this is a detached signature, we actually need to save both the
    # signature and the data to files and then run PGP on the signature file
    # to make it verify the signature.  Because this is a detached signature,
    # though, we don't have to do any data mangling, which makes our lives
    # much easier.  It would be nice to do this without having to use
    # temporary files, but I don't see any way to do so without running into
    # mangling problems.
    my $umask = umask 077;
    my $filename = $TMPDIR . '/pgp' . time . '.' . $$;
    my $sigfile = new FileHandle "$filename.asc", O_WRONLY|O_EXCL|O_CREAT;
    unless ($sigfile) {
        @ERROR = ("Unable to open temp file $filename.asc: $!\n");
        return undef;
    }
    print $sigfile "-----BEGIN PGP SIGNATURE-----\n";
    if (defined $version) {
        print $sigfile "Version: $version\n";
    }
    print $sigfile "\n", $signature;
    print $sigfile "\n-----END PGP SIGNATURE-----\n";
    close $sigfile;
    my $datafile = new FileHandle "$filename", O_WRONLY|O_EXCL|O_CREAT;
    unless ($datafile) {
        unlink "$filename.asc";
        @ERROR = ("Unable to open temp file $filename: $!\n");
        return undef;
    }
    unshift (@_, $datafile);
    &write_data;
    close $datafile;

    # Figure out what command line we'll be using.
    if ($PGPSTYLE ne 'GPG') {
        croak("Unknown \$PGPSTYLE setting $PGPSTYLE");
    }
    my @command = ($PGPV, '--batch', '--verify', '--quiet' ,'--status-fd=1',
                   '--logger-fd=1');

    # Now, call PGP to check the signature.  Because we've written everything
    # out to a file, this is actually fairly simple; all we need to do is grab
    # stdout.
    if ($PGPPATH) {
        push (@command, '--homedir', $PGPPATH);
    }
    push (@command, "$filename.asc");
    push (@command, $filename);
    my $pgp = new FileHandle;
    my $output = new FileHandle;
    my $pid = eval { open3 ($pgp, $output, $output, @command) };
    if ($@) {
        unlink ($filename, "$filename.asc");
        @ERROR = ($@, "Execution of $command[0] failed.\n");
        return undef;
    }
    close $pgp;

    # Check for the message that gives us the key status and return the
    # appropriate thing to our caller.
    #
    # GPG 1.4.23
    #   [GNUPG:] GOODSIG 7D80315C5736DE75 Russ Allbery <eagle@eyrie.org>
    #   [GNUPG:] BADSIG 7D80315C5736DE75 Russ Allbery <eagle@eyrie.org>
    local $_;
    local $/ = '';
    my $signer;
    while (<$output>) {
        if (/\[GNUPG:\]\s+GOODSIG\s+\S+\s+(.*)/) {
            $signer = $1;
            last;
        }
    }
    close $pgp;
    undef @ERROR;
    waitpid ($pid, 0);
    unlink ($filename, "$filename.asc");
    umask $umask;
    $signer ? $signer : '';
}

# Return the errors resulting from the last call to pgp_sign() or pgp_verify()
# or the empty list if there are none.
sub pgp_error {
    wantarray ? @ERROR : join ('', @ERROR);
}

##############################################################################
# Module return value and documentation
##############################################################################

# Make sure the module returns true.
1;

__DATA__

=head1 NAME

PGP::Sign - Create detached PGP signatures for data, securely

=head1 SYNOPSIS

    use PGP::Sign;
    ($signature, $version) = pgp_sign ($keyid, $passphrase, @data);
    $signer = pgp_verify ($signature, $version, @data);
    @errors = PGP::Sign::pgp_error;

=head1 DESCRIPTION

This module is designed to do one and only one thing securely and well;
namely, generate and check detached PGP signatures for some arbitrary data.
It doesn't do encryption, it doesn't manage keyrings, it doesn't verify
signatures, it just signs things.  This is ideal for applications like
PGPMoose or control message generation that just need a fast signing
mechanism.  It currently only supports GnuPG v1.

The interface is very simple; just call pgp_sign() with a key ID, a pass
phrase, and some data, or call pgp_verify() with a signature (in the form
generated by pgp_sign()), a version number (which can be undef if you don't
want to give a version), and some data.  The data can be specified in pretty
much any form you can possibly consider data and a few you might not.
Scalars and arrays are passed along to PGP; references to arrays are walked
and passed one element at a time (to avoid making a copy of the array); file
handles, globs, or references to globs are read a line at a time and passed
to PGP; and references to code are even supported (see below).  About the
only thing that we don't handle are references to references (which are just
printed to PGP, which probably isn't what you wanted) and hashes (which are
treated like arrays, which doesn't make a lot of sense).

If you give either function a reference to a sub, it will repeatedly call
that sub, sending the results to PGP to be signed, until the sub returns
undef.  What this lets you do is pass the function an anonymous sub that
walks your internal data and performs some manipulations on it a line at a
time, thus allowing you to sign a slightly modified form of your data (with
initial dashes escaped, for example) without having to use up memory to make
an internal copy of it.

In a scalar context, pgp_sign() returns the signature as an ASCII-armored
block with embedded newlines (but no trailing newline).  In a list context,
it returns a two-element list consisting of the signature as above and the
PGP version that signed it (if that information was present in the
signature).  Warning:  It's expected that in the future this interface will
change, and pgp_sign() will instead return a list consisting of the
ASCII-armored block and all headers found in the armor.

pgp_sign() will pass it the option B<--force-v3-sigs> so that it will generate
PGP 5.0-compatible signatures.

pgp_sign() will return undef in the event of any sort of error.

pgp_verify() returns the signer of the message in the case of a good
signature, the empty string in the case of a bad signature, and undef in the
event of some error.  It takes the same sort of data sources as pgp_sign().

pgp_error() (which isn't exported by default) returns the error encountered
by the last pgp_sign() or pgp_verify(), or undef if there was no error.  In
a list context, a list of lines is returned; in a scalar context, a long
string with embedded newlines is returned.

Six global variables can be modified (note that these may eventually be
partially or completely replaced with an interface via a PGP::Sign::config()
call):

=over 4

=item $PGP::Sign::PGPS

The path to the program to use to generate signatures.  Defaults to
C</usr/bin/gpg1>.

=item $PGP::Sign::PGPV

The path to the program to use to verify signatures.  Defaults to
C</usr/bin/gpg1>.

=item $PGP::Sign::PGPPATH

The path to a directory containing the PGP key rings that should be used.  If
this isn't set, GnuPG will use the value of the environment variable GNUPGHOME
or F<$HOME/.gnupg>.  If you're using GnuPG and the Entropy Gathering Daemon
(egd), the entropy socket or a link to it must be located in this directory.

=item $PGP::Sign::PGPSTYLE

What style of command line arguments and responses to expect from PGP.  The
only valid value for this variable is "GPG" for GnuPG behavior.

=item $PGP::Sign::TMPDIR

The directory in which temporary files are created.  Defaults to TMPDIR if
set, and F</tmp> if not.

=item $PGP::Sign::MUNGE

If this variable is set to a true value, PGP::Sign will automatically strip
trailing spaces when signing or verifying signatures.  This will make the
resulting signatures and verification compatible with programs that generate
attached signatures (since PGP ignores trailing spaces when generating or
checking attached signatures).  See the more extensive discussion of
whitespace below.

=back

=head1 ENVIRONMENT

=over 4

=item TMPDIR

The directory in which to create temporary files.  Can be overridden by
changing $PGP::Sign::TMPDIR.  If not set, defaults F</tmp>.

=back

In addition, all environment variables that GnuPG normally honors will be
passed along to GnuPG and will likely have their expected effects.  This
includes GNUPGHOME, unless it is overridden by setting C<$PGP::Sign::PGPPATH>.

=head1 DIAGNOSTICS

Mostly the contents of @PGP::Sign::ERROR (returned by pgp_error()) are just
the output of PGP.  The exceptions are:

=over 4

=item Execution of %s failed: %s

We couldn't fork off a PGP process for some reason, given (at least as the
system reported it) after the colon.

=item No signature from PGP (command not found?)

We tried to generate a signature but the output from the command we tried to
run didn't contain anything that looked like a signature.  One common
explanation for this is that the path in $PGP::Sign::PGPS is invalid and
that binary doesn't exist.

=item %s returned exit status %d

Some command that we ran, or tried to run, returned a non-zero exit status.
%s will contain the exact binary name that PGP::Sign was attempting to run.

=back

=head1 BUGS

PGP::Sign does not currently work with binary data, as it unconditionally
forces text mode in PGP by using the C<-t> option.  This is a high priority
to fix, but I'd like to implement some sort of generic way of setting PGP
options rather than just adding more entry points.

There's no way of generating version four DSS signatures.  This will be
fixed by the same improvement that will fix the previous bug.

PGP, all versions that I have available, behaves differently when generating
attached signatures than when generating detached signatures.  For attached
signatures, trailing whitespace in lines of the data is not significant, but
for detached signatures it is.  This, combined with the fact that there's no
way that I can see to get PGP to verify a detached signature without using
files on disk, means that in order to maintain the intended default
semantics of this module (manipulating detached signatures), I had to use
temporary files in the implementation of pgp_verify().  PGP::Sign sets its
umask before creating those temporary files and opens them with O_EXCL, but
files may be left behind in the event that an application using pgp_verify()
crashes unexpectedly.  Setting $PGP::Sign::TMPDIR is recommended.

Also, because of this incompatibility, you need to be aware of what the
process checking the signatures you generate is expecting.  If that process
is going to turn your signature into an attached signature for verification
(as pgpverify does for Usenet control messages), then you need to pre-munge
your data to remove trailing whitespace at the ends of lines before feeding
it to PGP.  PGP::Sign will do that for you if you set $PGP::Sign::MUNGE to a
true value.

To add even more confusion to the mix, earlier versions of GnuPG followed an
interpretation of RFC 2440 that specified text-mode signatures are performed
against data with canonicalized line endings and with trailing whitespace
removed (see section 5.2.1).  There is no difference specified there between
attached and detached signatures, and GnuPG treated them both the same.
Versions of GnuPG at least after 1.0 appear to have changed to follow the
PGP behavior instead.

When verification of a signature fails, currently not very much information
about what failed is available (since an invalid signature isn't considered
an error in the pgp_error() sense).

=head1 CAVEATS

This module is fairly good at what it does, but it doesn't do very much.  At
one point, I had plans to provide more options and more configurability in
the future, particularly the ability to handle binary data, that would
probably mean API changes.  I'm not sure at this point whether I'll get to
that, or just replace this module with one that only uses GnuPG as I see no
reason to use any other PGP implementation at this point and GnuPG has a
much nicer programmatic interface.

However, just in case, the interface to this module should not be considered
stable yet; you may have to change your application when you upgrade to a
newer version of this module.  The README will list API changes.

=head1 RESTRICTIONS

PGP::Sign passes pass phrases to PGP via an open one-ended pipe, since this
is the only secure method (both command line switches and environment
variables can potentially be read by other users on the same machine using
ps).  This should be supported by any recent version of PGP; I have tested
it against 2.6.2, 2.6.3i, 5.0, 6.5.2, GnuPG 0.9.2, and GnuPG 1.0.1.
Implicit in this mechanism, though, is the requirement that the operating
system on which you're running this module supports passing an open pipe to
an exec()ed subprocess.  This may cause portability problems to certain
substandard operating systems.

=head1 HISTORY

Based heavily on work by Andrew Gierth and benefitting greatly from input,
comments, suggestions, and help from him, this module came about in the
process of implementing PGPMoose signatures and control message signatures
for Usenet.  PGPMoose is the idea of Greg Rose, and signcontrol and
pgpverify are the idea of David Lawrence.

Support for PGPPATH, the test suite, some bug fixes, and the impetus to get
another version released came from Andrew Ford.  Thank you.

Original support for GnuPG from Todd Underwood and Monte Mitzelfelt.  Code
for using --status-fd based on code by Marco d'Itri.

=head1 AUTHOR

Russ Allbery <rra@cpan.org>

=head1 COPYRIGHT AND LICENSE

Copyright 1997-2000, 2002, 2004, 2018, 2020 Russ Allbery <rra@cpan.org>

This program is free software; you may redistribute it and/or modify it
under the same terms as Perl itself.

=head1 SEE ALSO

gpg1(1)

RFC 2440, L<http://www.rfc-editor.org/rfc/rfc2440.txt>, which specifies the
OpenPGP message format.

The current version of this module is always available from its web site at
L<http://www.eyrie.org/~eagle/software/pgp-sign/>.

=cut

# Local Variables:
# copyright-at-end-flag: t
# End:
