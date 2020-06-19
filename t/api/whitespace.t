#!/usr/bin/perl
#
# Basic tests for PGP::Sign functionality.
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

use IO::File;
use Test::More tests => 13;

BEGIN {
    use_ok('PGP::Sign', qw(pgp_sign pgp_verify pgp_error));
}

# Locate our test data directory for later use.
my $data = 't/data';
$PGP::Sign::PGPPATH = $data;

# The key ID and pass phrase to use for testing.
my $keyid      = 'testing';
my $passphrase = 'testing';

# Sign a message consisting solely of whitespace and verify it.
my ($signature, $version) = pgp_sign($keyid, $passphrase, q{       });
is(pgp_verify($signature, $version, q{       }), $keyid, 'Pure whitespace');

# Do the same with whitespace munging enabled, and verify that it matches the
# signature of the empty string.
{
    local $PGP::Sign::MUNGE = 1;
    ($signature, $version) = pgp_sign($keyid, $passphrase, q{       });
}
is(pgp_verify($signature, $version, q{       }), q{}, "Munged doesn't match");
is(pgp_verify($signature, $version, q{}), $keyid, '...but does match empty');

# Put the newline in the next chunk of data and confirm that it is still
# munged correctly.
my @message = ('foo    ', "\n  bar   ", "  \nbaz    ");
{
    local $PGP::Sign::MUNGE = 1;
    ($signature, $version) = pgp_sign($keyid, $passphrase, @message);
}
is(
    pgp_verify($signature, $version, "foo\n  bar\nbaz"),
    $keyid,
    'Munging works when separated from newline'
);

# Open and load a more comprehensive data file.
open(my $fh, '<', "$data/message");
my @data = <$fh>;
close($fh);

# Create a version of the data with whitespace at the end of each line and
# then generate a signature with munging enabled.
my @whitespace = @data;
for my $line (@whitespace) {
    $line =~ s{\n}{ \n}xms;
}
{
    local $PGP::Sign::MUNGE = 1;
    ($signature, $version) = pgp_sign($keyid, $passphrase, @whitespace);
}
isnt($signature, undef, 'Signature of munged data');
is(pgp_error(), q{}, '...with no errors');

# This signature should be over the same content as @data, so should verify
# when given @data as the message.
is(pgp_verify($signature, $version, @data), $keyid, 'Verifies');
is(pgp_error(), q{}, '...with no errors');

# This signature should also verify when mugning of the data is enabled.
{
    local $PGP::Sign::MUNGE = 1;
    my $signer = pgp_verify($signature, $version, @whitespace);
    is($signer, $keyid, 'Verifies with munging');
}
is(pgp_error(), q{}, '...with no errors');

# If the data is not munged on verification, it will not match, since GnuPG
# treats the trailing whitespace as significant.
my $signer = pgp_verify($signature, $version, @whitespace);
is($signer,     q{}, 'Fails to verifies without munging');
is(pgp_error(), q{}, '...with no errors');
