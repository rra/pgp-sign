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

package PGP::Sign 1.00;

use 5.020;
use autodie;
use warnings;

use Carp qw(croak);
use Exporter qw(import);
use File::Temp ();
use IO::Handle;
use IPC::Run qw(finish run start timeout);
use Scalar::Util qw(blessed);

# Export pgp_sign and pgp_verify by default for backwards compatibility.
## no critic (Modules::ProhibitAutomaticExportation)
our @EXPORT    = qw(pgp_sign pgp_verify);
our @EXPORT_OK = qw(pgp_error);
## use critic

# The flags to use with the various PGP styles.
my %SIGN_FLAGS = (
    GPG => [
        qw(
          --detach-sign --armor
          --quiet --textmode --batch --no-tty --pinentry-mode=loopback
          --no-greeting --no-permission-warning
          )
    ],
    GPG1 => [
        qw(
          --detach-sign --armor
          --quiet --textmode --batch --no-tty --no-use-agent
          --no-greeting --no-permission-warning
          --force-v3-sigs --allow-weak-digest-algos
          )
    ],
);
my %VERIFY_FLAGS = (
    GPG => [
        qw(
          --verify
          --quiet --batch --no-tty
          --no-greeting --no-permission-warning
          --no-auto-key-retrieve --no-auto-check-trustdb
          --allow-weak-digest-algos
          --disable-dirmngr
          )
    ],
    GPG1 => [
        qw(
          --verify
          --quiet --batch --no-tty
          --no-greeting --no-permission-warning
          --no-auto-key-retrieve --no-auto-check-trustdb
          --allow-weak-digest-algos
          )
    ],
);

##############################################################################
# Old global variables
##############################################################################

# These variables are part of the legacy PGP::Sign interface and are
# maintained for backward compatibility.  They are only used by the legacy
# pgp_sign and pgp_verify functions, not by the new object-oriented API.

# Whether or not to perform some standard whitespace munging to make other
# signing and checking routines happy.
our $MUNGE = 0;

# The default path to PGP.  PGPS is for signing, PGPV is for verifying.
# (There's no reason to use separate commands any more, but with PGPv5 these
# were two different commands, so this became part of the legacy API.)
our $PGPS;
our $PGPV;

# The path to the directory containing the key ring.  If not set, defaults to
# $ENV{GNUPGHOME} or $HOME/.gnupg.
our $PGPPATH;

# What style of PGP invocation to use by default.  If not set, defaults to the
# default style for the object-oriented API.
our $PGPSTYLE;

# The directory in which temporary files should be created.  If not set,
# defaults to whatever File::Temp decides to use.
our $TMPDIR;

# Used by pgp_sign and pgp_verify to store errors returned by the
# object-oriented API so that they can be returned via pgp_error.
my @ERROR = ();

##############################################################################
# Utility functions
##############################################################################

# print with error checking and an explicit file handle.  autodie
# unfortunately can't help us with these because they can't be prototyped and
# hence can't be overridden.
#
# $fh   - Output file handle
# @args - Remaining arguments to print
#
# Returns: undef
#  Throws: Text exception on output failure
sub _print_fh {
    my ($fh, @args) = @_;
    print {$fh} @args or croak('print failed');
    return;
}

##############################################################################
# Object-oriented interface
##############################################################################

# Create a new PGP::Sign object encapsulating the configuration.
#
# $args_ref - Anonymous hash of arguments with the following keys:
#   home   - Path to the GnuPG homedir containing keyrings
#   munge  - Boolean indicating whether to munge whitespace
#   path   - Path to the GnuPG binary to use
#   style  - Style of OpenPGP backend to use
#   tmpdir - Directory to use for temporary files
#
# Returns: Newly created object
#  Throws: Text exception for an invalid OpenPGP backend style
sub new {
    my ($class, $args_ref) = @_;

    # Check the style argument.
    my $style = $args_ref->{style} || 'GPG';
    if ($style ne 'GPG' && $style ne 'GPG1') {
        croak("Unknown OpenPGP backend style $style");
    }

    # If path is not given, set a default based on the style.
    my $path = $args_ref->{path} // lc($style);

    # Create and return the object.
    my $self = {
        home   => $args_ref->{home},
        munge  => $args_ref->{munge},
        path   => $path,
        style  => $style,
        tmpdir => $args_ref->{tmpdir},
    };
    bless($self, $class);
    return $self;
}

# This function actually sends the data to a file handle.  It's necessary to
# implement munging (stripping trailing spaces on a line).
#
# $fh     - The file handle to which to write the data
# $string - The data to write
sub _write_string {
    my ($self, $fh, $string) = @_;

    # If there were any left-over spaces from the last invocation, prepend
    # them to the string and clear them.
    if ($self->{spaces}) {
        $string = $self->{spaces} . $string;
        $self->{spaces} = q{};
    }

    # If whitespace munging is enabled, strip any trailing whitespace from
    # each line of the string for which we've seen the newline.  Then, remove
    # and store any spaces at the end of the string, since the newline may be
    # in the next chunk.
    #
    # If there turn out to be no further chunks, this removes any trailing
    # whitespace on the last line without a newline, which is still correct.
    if ($self->{munge}) {
        $string =~ s{ [ ]+ \n }{\n}xmsg;
        if ($string =~ s{ ([ ]+) \Z }{}xms) {
            $self->{spaces} = $1;
        }
    }

    _print_fh($fh, $string);
    return;
}

# This is our generic "take this data and shove it" routine, used both for
# signature generation and signature checking.  Scalars, references to arrays,
# references to IO::Handle objects, file globs, references to code, and
# references to file globs are all supported as ways to get the data, and at
# most one line at a time is read (cutting down on memory usage).
#
# References to code are an interesting subcase.  A code reference is executed
# repeatedly, passing whatever it returns to GnuPG, until it returns undef.
#
# $fh      - The file handle to which to write the data
# @sources - The data to write, in any of those formats
sub _write_data {
    my ($self, $fh, @sources) = @_;
    $self->{spaces} = q{};

    # Deal with all of our possible sources of input, one at a time.
    #
    # We can't do anything interesting or particularly "cool" with references
    # to references, so those we just print.  (Perl allows circular
    # references, so we can't just dereference references to references until
    # we get something interesting.)
    for my $source (@sources) {
        if (ref($source) eq 'ARRAY') {
            for my $chunk (@$source) {
                $self->_write_string($fh, $chunk);
            }
        } elsif (ref($source) eq 'GLOB' || ref(\$source) eq 'GLOB') {
            while (defined(my $chunk = <$source>)) {
                $self->_write_string($fh, $chunk);
            }
        } elsif (ref($source) eq 'SCALAR') {
            $self->_write_string($fh, $$source);
        } elsif (ref($source) eq 'CODE') {
            while (defined(my $chunk = &$source())) {
                $self->_write_string($fh, $chunk);
            }
        } elsif (blessed($source)) {
            if ($source->isa('IO::Handle')) {
                while (defined(my $chunk = <$source>)) {
                    $self->_write_string($fh, $chunk);
                }
            } else {
                $self->_write_string($fh, $source);
            }
        } else {
            $self->_write_string($fh, $source);
        }
    }
    return;
}

# Construct the command for signing.  This will expect the passphrase on file
# descriptor 3.
#
# $keyid - The OpenPGP key ID with which to sign
#
# Returns: List of the command and arguments.
sub _build_sign_command {
    my ($self, $keyid) = @_;
    my @command = ($self->{path}, '-u', $keyid, qw(--passphrase-fd 3));
    push(@command, @{ $SIGN_FLAGS{ $self->{style} } });
    if ($self->{home}) {
        push(@command, '--homedir', $self->{home});
    }
    return @command;
}

# Construct the command for verification.  This will send all status and
# logging to standard output.
#
# $signature_file - Path to the file containing the signature
# $data_file      - Path to the file containing the signed data
#
# Returns: List of the command and arguments.
sub _build_verify_command {
    my ($self, $signature_file, $data_file) = @_;
    my @command = ($self->{path}, qw(--status-fd 1 --logger-fd 1));
    push(@command, @{ $VERIFY_FLAGS{ $self->{style} } });
    if ($self->{home}) {
        push(@command, '--homedir', $self->{home});
    }
    push(@command, $signature_file, $data_file);
    return @command;
}

# Create a detached signature for the given data.
#
# $keyid      - GnuPG key ID to use to sign the data
# $passphrase - Passphrase for the GnuPG key
# @sources    - The data to sign (see _write_data for more information)
#
# Returns: The signature as an ASCII-armored block with embedded newlines
#  Throws: Text exception on failure that includes the GnuPG output
sub sign {
    my ($self, $keyid, $passphrase, @sources) = @_;

    # Ignore SIGPIPE, since we're going to be talking to GnuPG.
    local $SIG{PIPE} = 'IGNORE';

    # Build the command to run.
    my @command = $self->_build_sign_command($keyid);

    # Fork off a pgp process that we're going to be feeding data to, and tell
    # it to just generate a signature using the given key id and pass phrase.
    my $writefh = IO::Handle->new();
    my ($signature, $errors);
    #<<<
    my $h = start(
        \@command,
        '3<', \$passphrase,
        '<pipe', $writefh,
        '>', \$signature,
        '2>', \$errors,
    );
    #>>>
    $self->_write_data($writefh, @sources);
    close($writefh);

    # Get the return status and raise an exception on failure.
    if (!finish($h)) {
        my $status = $h->result();
        $errors .= "Execution of $command[0] failed with status $status";
        croak($errors);
    }

    # The resulting signature will look something like this:
    #
    # -----BEGIN PGP SIGNATURE-----
    # Version: GnuPG v0.9.2 (SunOS)
    # Comment: For info see http://www.gnupg.org
    #
    # iEYEARECAAYFAjbA/fsACgkQ+YXjQAr8dHYsMQCgpzOkRRopdW0nuiSNMB6Qx2Iw
    # bw0AoMl82UxQEkh4uIcLSZMdY31Z8gtL
    # =Dj7i
    # -----END PGP SIGNATURE-----
    #
    # Find and strip the marker line for the start of the signature.
    my @signature = split(m{\n}xms, $signature);
    while ((shift @signature) !~ m{-----BEGIN [ ] PGP [ ] SIGNATURE-----}xms) {
        if (!@signature) {
            croak('No signature returned by GnuPG');
        }
    }

    # Strip any headers off the signature.  Thankfully all of the important
    # data is encoded into the signature itself, so the headers aren't needed.
    while (@signature && $signature[0] ne q{}) {
        shift(@signature);
    }
    shift(@signature);

    # Remove the trailing marker line.
    pop(@signature);

    # Everything else is the signature that we want.
    return join("\n", @signature);
}

# Check a detatched signature for given data.
#
# $signature - The signature as an ASCII-armored string with embedded newlines
# @sources   - The data over which to check the signature
#
# Returns: The human-readable key ID of the signature, or an empty string if
#          the signature did not verify
#  Throws: Text exception on an error other than a bad signature
sub verify {
    my ($self, $signature, @sources) = @_;
    chomp($signature);

    # Ignore SIGPIPE, since we're going to be talking to PGP.
    local $SIG{PIPE} = 'IGNORE';

    # To verify a detached signature, we need to save both the signature and
    # the data to files and then run GnuPG on the pair of files.  There
    # doesn't appear to be a way to feed both the data and the signature in on
    # file descriptors.
    my @tmpdir = defined($self->{tmpdir}) ? (DIR => $self->{tmpdir}) : ();
    my $sigfh  = File::Temp->new(@tmpdir, SUFFIX => '.asc');
    _print_fh($sigfh, "-----BEGIN PGP SIGNATURE-----\n");
    _print_fh($sigfh, "\n", $signature);
    _print_fh($sigfh, "\n-----END PGP SIGNATURE-----\n");
    close($sigfh);
    my $datafh = File::Temp->new(@tmpdir);
    $self->_write_data($datafh, @sources);
    close($datafh);

    # Build the command to run.
    my @command
      = $self->_build_verify_command($sigfh->filename, $datafh->filename);

    # Call GnuPG to check the signature.  Because we've written everything out
    # to a file, this is fairly simple; just grab stdout.
    my $output;
    run(\@command, '>&', \$output);
    my $status = $?;

    # Check for the message that gives us the key status and return the
    # appropriate thing to our caller.
    #
    # GPG 1.4.23
    #   [GNUPG:] GOODSIG 7D80315C5736DE75 Russ Allbery <eagle@eyrie.org>
    #   [GNUPG:] BADSIG 7D80315C5736DE75 Russ Allbery <eagle@eyrie.org>
    #
    # Note that this returns the human-readable key ID instead of the actual
    # key ID.  This is a historical wart in the API; a future version will
    # hopefully add an option to return more accurate signer information.
    for my $line (split(m{\n}xms, $output)) {
        if ($line =~ m{ \[GNUPG:\] \s+ GOODSIG \s+ \S+ \s+ (.*)}xms) {
            return $1;
        } elsif ($line =~ m{ ^ \[GNUPG:\] \s+ BADSIG \s+ }xms) {
            return q{};
        }
    }

    # Neither a good nor a bad signature seen.
    if ($status != 0) {
        $output .= "Execution of $command[0] failed with status $status";
    }
    croak($output);
}

##############################################################################
# Legacy function API
##############################################################################

# This is the original API from 0.x versions of PGP::Sign.  It is maintained
# for backwards compatibility, but is now a wrapper around the object-oriented
# API that uses the legacy global variables.  The object-oriented API should
# be preferred for all new code.

# Create a detached signature for the given data.
#
# The original API returned the PGP implementation version from the signature
# headers as the second element of the list returned in array context.  This
# information is pointless and unnecessary and GnuPG doesn't include that
# header by default, so the fixed string "GnuPG" is now returned for backwards
# compatibility.
#
# Errors are stored for return by pgp_error(), overwriting any previously
# stored error.
#
# $keyid      - GnuPG key ID to use to sign the data
# $passphrase - Passphrase for the GnuPG key
# @sources    - The data to sign (see _write_data for more information)
#
# Returns: The signature as an ASCII-armored block in scalar context
#          The signature and the string "GnuPG" in list context
#          undef or the empty list on error
sub pgp_sign {
    my ($keyid, $passphrase, @sources) = @_;
    @ERROR = ();

    # Create the signer object.
    my $signer = PGP::Sign->new(
        {
            home   => $PGPPATH,
            munge  => $MUNGE,
            path   => $PGPS,
            style  => $PGPSTYLE,
            tmpdir => $TMPDIR,
        }
    );

    # Do the work, capturing any errors.
    my $signature = eval { $signer->sign($keyid, $passphrase, @sources) };
    if ($@) {
        @ERROR = split(m{\n}xms, $@);
        return;
    }

    # Return the results, including a dummy version if desired.
    return wantarray ? ($signature, 'GnuPG') : $signature;
}

# Check a detatched signature for given data.
#
# $signature - The signature as an ASCII-armored string with embedded newlines
# @sources   - The data over which to check the signature
#
# Returns: The human-readable key ID of the signature
#          An empty string if the signature did not verify
#          undef on error
sub pgp_verify {
    my ($signature, $version, @sources) = @_;
    @ERROR = ();

    # Create the verifier object.
    my $verifier = PGP::Sign->new(
        {
            home   => $PGPPATH,
            munge  => $MUNGE,
            path   => $PGPV,
            style  => $PGPSTYLE,
            tmpdir => $TMPDIR,
        }
    );

    # Do the work, capturing any errors.
    my $signer = eval { $verifier->verify($signature, @sources) };
    if ($@) {
        @ERROR = split(m{\n}xms, $@);
        return;
    }

    # Return the results.
    return $signer;
}

# Retrieve errors from the previous pgp_sign() or pgp_verify() call.
#
# Historically the pgp_error() return value in list context had newlines at
# the end of each line, so add them back in.
#
# Returns: A list of GnuPG output and error messages in list context
#          The block of GnuPG output and error message in scalar context
sub pgp_error {
    my @error_lines = map { "$_\n" } @ERROR;
    return wantarray ? @error_lines : join(q{}, @error_lines);
}

##############################################################################
# Module return value and documentation
##############################################################################

# Make sure the module returns true.
1;

__DATA__

=for stopwords
Allbery DSS GNUPGHOME GPG GPG1 Gierth Mitzelfelt OpenPGP PGPMoose PGPPATH
TMPDIR canonicalized d'Itri egd keyrings pgpverify ps signcontrol

=head1 NAME

PGP::Sign - Create detached PGP signatures for data, securely

=head1 SYNOPSIS

    use PGP::Sign;
    my $keyid = '<some-key-id>';
    my $passphrase = '<passphrase-for-key>';
    my @data = ('lines to', 'be signed');
    my ($signature, $version) = pgp_sign ($keyid, $passphrase, @data);
    my $signer = pgp_verify ($signature, $version, @data);
    my @errors = PGP::Sign::pgp_error;

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

pgp_sign() will pass it the option C<--force-v3-sigs> so that it will generate
PGP 5.0-compatible signatures, and C<--allow-weak-digest-algos> so that it can
use old PGP keys.

pgp_sign() will return undef in the event of any sort of error.

pgp_verify() returns the signer of the message in the case of a good
signature, the empty string in the case of a bad signature, and undef in the
event of some error.  It takes the same sort of data sources as pgp_sign().
It will pass the option C<--allow-weak-digest-algos> so that it can verify old
signatures.

pgp_error() (which isn't exported by default) returns the error encountered
by the last pgp_sign() or pgp_verify(), or undef if there was no error.  In
a list context, a list of lines is returned; in a scalar context, a long
string with embedded newlines is returned.

Six global variables can be modified (note that these may eventually be
partially or completely replaced with an interface via a PGP::Sign::config()
call):

=over 4

=item $PGP::Sign::PGPS

The path to the program to use to generate signatures.  Defaults to searching
for C<gpg1> on the user's PATH.

=item $PGP::Sign::PGPV

The path to the program to use to verify signatures.  Defaults to searching
for C<gpg1> on the user's PATH.

=item $PGP::Sign::PGPPATH

The path to a directory containing the PGP key rings that should be used.  If
this isn't set, GnuPG will use the value of the environment variable GNUPGHOME
or F<$HOME/.gnupg>.  If you're using GnuPG and the Entropy Gathering Daemon
(egd), the entropy socket or a link to it must be located in this directory.

=item $PGP::Sign::PGPSTYLE

What style of command line arguments and responses to expect from PGP.  Must
be either "GPG" for GnuPG v2 or "GPG1" for GnuPG v1.  The default is "GPG1".

=item $PGP::Sign::TMPDIR

The directory in which temporary files are created.  Defaults to whatever
directory File::Temp chooses to use by default.

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
(as B<pgpverify> does for Usenet control messages), then you need to pre-munge
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
B<ps>).  This should be supported by any recent version of PGP; I have tested
it against 2.6.2, 2.6.3i, 5.0, 6.5.2, GnuPG 0.9.2, and GnuPG 1.0.1.
Implicit in this mechanism, though, is the requirement that the operating
system on which you're running this module supports passing an open pipe to
an exec()ed subprocess.  This may cause portability problems to certain
substandard operating systems.

=head1 HISTORY

Based heavily on work by Andrew Gierth and benefiting greatly from input,
comments, suggestions, and help from him, this module came about in the
process of implementing PGPMoose signatures and control message signatures
for Usenet.  PGPMoose is the idea of Greg Rose, and B<signcontrol> and
B<pgpverify> are the idea of David Lawrence.

Support for PGPPATH, the test suite, some bug fixes, and the impetus to get
another version released came from Andrew Ford.  Thank you.

Original support for GnuPG from Todd Underwood and Monte Mitzelfelt.  Code
for using C<--status-fd> based on code by Marco d'Itri.

=head1 AUTHOR

Russ Allbery <rra@cpan.org>

=head1 COPYRIGHT AND LICENSE

Copyright 1997-2000, 2002, 2004, 2018, 2020 Russ Allbery <rra@cpan.org>

This program is free software; you may redistribute it and/or modify it
under the same terms as Perl itself.

=head1 SEE ALSO

gpg1(1), L<File::Temp>

RFC 2440, L<http://www.rfc-editor.org/rfc/rfc2440.txt>, which specifies the
OpenPGP message format.

The current version of this module is always available from its web site at
L<https://www.eyrie.org/~eagle/software/pgp-sign/>.

=cut

# Local Variables:
# copyright-at-end-flag: t
# End:
