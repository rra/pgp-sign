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

use File::Spec;
use IO::File;
use Test::More tests => 20;

BEGIN { use_ok('PGP::Sign'); }

# Locate our test data directory for later use.
my $data = 't/data';
$PGP::Sign::PGPPATH = File::Spec->catdir($data, 'gnupg1');

# Open and load our data file.  This is the sample data that we'll be signing
# and checking signatures against.
open(my $fh, '<', "$data/message");
my @data = <$fh>;
close($fh);

# The key ID and pass phrase to use for testing.
my $keyid      = 'testing';
my $passphrase = 'testing';

# Generate a signature and then verify it.
my ($signature, $version) = pgp_sign($keyid, $passphrase, @data);
ok($signature, 'Sign');
is(PGP::Sign::pgp_error(), q{}, '...with no errors');
isnt($signature, undef, 'Signature');
is(PGP::Sign::pgp_error(), q{}, '...with no errors');

# Check signature.
is(pgp_verify($signature, $version, @data), $keyid, 'Verify');
is(PGP::Sign::pgp_error(),                  q{},    '...with no errors');

# The same without version, which shouldn't matter.
is(pgp_verify($signature, undef, @data), $keyid, 'Verify without version');
is(PGP::Sign::pgp_error(),               q{},    '...with no errors');

# Check a failed signature by appending some nonsense to the data.
is(pgp_verify($signature, $version, @data, 'xyzzy'), q{}, 'Verify invalid');
is(PGP::Sign::pgp_error(),                           q{}, '...with no errors');

# Test taking code from a code ref and then verifying the reulting signature.
# Also test accepting only one return value from pgp_sign().
my @code_input = @data;
my $data_ref   = sub {
    my $line = shift(@code_input);
    return $line;
};
$signature = pgp_sign($keyid, $passphrase, $data_ref);
isnt($signature, undef, 'Signature from code ref');
is(PGP::Sign::pgp_error(),                  q{},    '...with no errors');
is(pgp_verify($signature, $version, @data), $keyid, 'Verifies');
is(PGP::Sign::pgp_error(),                  q{},    '...with no errors');

# Avoid test warnings about using my obsolete address.  For better or worse,
# this was the UID used to generate that signature, and I don't want to
# regenerate it since the point of the test is to check signatures generated
# by obsolete versions.
my $expected = 'Russ Allbery <rra@' . 'stanford.edu>';

# Check an external version three DSA signature with data from an array ref.
open($fh, '<', "$data/message.asc");
my @raw_signature = <$fh>;
close($fh);
$signature = join(q{}, @raw_signature[4 .. 6]);
my $signer = pgp_verify($signature, undef, \@data);
is($signer,                $expected, 'DSAv3 sig from array ref');
is(PGP::Sign::pgp_error(), q{},       '...with no errors');

# Check an external version four DSA signature from an IO::Handle.
open($fh, '<', "$data/message.asc.v4");
@raw_signature = <$fh>;
close($fh);
$signature = join(q{}, @raw_signature[4 .. 6]);
$signer = pgp_verify($signature, undef, IO::File->new("$data/message", 'r'));
is(PGP::Sign::pgp_error(), q{}, '...with no errors');

# Check an ancient PGP 2.x signature.
open($fh, '<', "$data/message.sig");
@raw_signature = <$fh>;
close($fh);
$signature = join(q{}, @raw_signature[3 .. 6]);
$signer    = pgp_verify($signature, undef, \@data);
is(
    $signer,
    'R. Russell Allbery <eagle@windlord.stanford.edu>',
    'PGP sig from array ref'
);
is(PGP::Sign::pgp_error(), q{}, '...with no errors');
