#!/usr/bin/perl
#
# Tests for PGP::Sign whitespace munging.
#
# Copyright 1998-2001, 2004, 2007, 2018, 2020 Russ Allbery <rra@cpan.org>
#
# This program is free software; you may redistribute it and/or modify it
# under the same terms as Perl itself.
#
# SPDX-License-Identifier: GPL-1.0-or-later OR Artistic-1.0-Perl

use 5.020;
use autodie;
use warnings;

use lib 't/lib';

use File::Spec;
use IO::File;
use IPC::Cmd qw(can_run);
use Test::More;
use Test::PGP qw(gpg_is_gpg1 gpg_is_new_enough);

# Check that GnuPG is available.  If so, load the module and set the plan.
BEGIN {
    if (!can_run('gpg')) {
        plan skip_all => 'gpg binary not available';
    } elsif (!gpg_is_new_enough('gpg')) {
        plan skip_all => 'gpg binary is older than 1.4.20 or 2.1.23';
    } else {
        plan tests => 10;
        use_ok('PGP::Sign');
    }
}

# The key ID and pass phrase to use for testing.
my $keyid = 'testing';
my $passphrase = 'testing';

# Create the objects to use for tests, one without munging enabled and one
# with.
my ($home, $signer, $munged);
if (gpg_is_gpg1()) {
    $home = File::Spec->catdir('t', 'data', 'gnupg1');
    $signer = PGP::Sign->new(
        {
            home => $home,
            path => 'gpg',
            style => 'GPG1',
        },
    );
    $munged = PGP::Sign->new(
        {
            home => $home,
            path => 'gpg',
            munge => 1,
            style => 'GPG1',
        },
    );
} else {
    $home = File::Spec->catdir('t', 'data', 'gnupg2');
    $signer = PGP::Sign->new({ home => $home });
    $munged = PGP::Sign->new({ home => $home, munge => 1 });
}

# Sign a message consisting solely of whitespace and verify it.
my $signature = $signer->sign($keyid, $passphrase, q{       });
is($keyid, $signer->verify($signature, q{       }), 'Pure whitespace');

# Do the same with whitespace munging enabled, and verify that it matches the
# signature of the empty string.
$signature = $munged->sign($keyid, $passphrase, q{       });
is(q{}, $signer->verify($signature, q{       }), 'Munged does not match');
is($keyid, $signer->verify($signature, q{}), '...but does match empty');
is($keyid, $munged->verify($signature, q{       }), '...and munge matches');
is($keyid, $munged->verify($signature, q{}), '...either one');

# Put the newline in the next chunk of data and confirm that it is still
# munged correctly.
my @message = ('foo    ', "\n  bar   ", "  \nbaz    ");
$signature = $munged->sign($keyid, $passphrase, \@message);
is(
    $keyid,
    $signer->verify($signature, "foo\n  bar\nbaz"),
    'Munging works when separated from newline',
);

# Open and load a more comprehensive data file.
open(my $fh, '<', 't/data/message');
my @data = <$fh>;
close($fh);

# Create a version of the data with whitespace at the end of each line and
# then generate a signature with munging enabled.  This signature should be
# over the same content as @data, so should verify when given @data as the
# message.
my @whitespace = @data;
for my $line (@whitespace) {
    $line =~ s{\n}{ \n}xms;
}
$signature = $munged->sign($keyid, $passphrase, @whitespace);
is($keyid, $signer->verify($signature, @data), 'Longer data verifies');

# This signature should also verify when mugning of the data is enabled.
is($keyid, $munged->verify($signature, @whitespace), 'Verifies with munging');

# If the data is not munged on verification, it will not match, since GnuPG
# treats the trailing whitespace as significant.
is(q{}, $signer->verify($signature, @whitespace), 'Fails without munging');
