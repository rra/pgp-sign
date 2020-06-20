#!/usr/bin/perl
#
# Test existing signatures.
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
use Test::More tests => 11;

BEGIN { use_ok('PGP::Sign'); }

# Locate our test data directory for later use.
my $data = 't/data';

# Open and load our data file.  This is the sample data that we'll be signing
# and checking signatures against.
open(my $fh, '<', "$data/message");
my @data = <$fh>;
close($fh);

# Start with testing signatures with GnuPG v2.
local $PGP::Sign::PGPSTYLE = 'GPG';
local $PGP::Sign::PGPPATH  = File::Spec->catdir($data, 'gnupg2');
local $PGP::Sign::PGPS     = 'gpg';
local $PGP::Sign::PGPV     = 'gpg';

# Check a modern RSA signature using a scalar reference as the data source.
open($fh, '<', "$data/message.rsa-v4.asc");
my @raw_signature = <$fh>;
close($fh);
my $signature   = join(q{}, @raw_signature[2 .. 11]);
my $scalar_data = join(q{}, @data);
my $signer      = pgp_verify($signature, undef, \$scalar_data);
is($signer,                'testing', 'RSAv4 sig from scalar ref');
is(PGP::Sign::pgp_error(), q{},       '...with no errors');

# Check a version 3 RSA signature using a scalar as the data source.
open($fh, '<', "$data/message.rsa-v3.asc");
@raw_signature = <$fh>;
close($fh);
$signature = join(q{}, @raw_signature[2 .. 11]);
$signer    = pgp_verify($signature, undef, $scalar_data);
is($signer,                'testing', 'RSAv3 sig from scalar');
is(PGP::Sign::pgp_error(), q{},       '...with no errors');

# The remaining tests are for old signatures using a key that GnuPG v2 does
# not support.
local $PGP::Sign::PGPSTYLE = 'GPG1';
local $PGP::Sign::PGPPATH  = File::Spec->catdir($data, 'gnupg1');
local $PGP::Sign::PGPS     = 'gpg1';
local $PGP::Sign::PGPV     = 'gpg1';

# Avoid test warnings about using my obsolete address.  For better or worse,
# this was the UID used to generate that signature, and I don't want to
# regenerate it since the point of the test is to check signatures generated
# by obsolete versions.
my $expected = 'Russ Allbery <rra@' . 'stanford.edu>';

# Check an external version three DSA signature with data from an array ref.
open($fh, '<', "$data/message.dsa-v3.asc");
@raw_signature = <$fh>;
close($fh);
$signature = join(q{}, @raw_signature[4 .. 6]);
$signer    = pgp_verify($signature, undef, \@data);
is($signer,                $expected, 'DSAv3 sig from array ref');
is(PGP::Sign::pgp_error(), q{},       '...with no errors');

# Check an external version four DSA signature from an IO::Handle.
open($fh, '<', "$data/message.dsa-v4.asc");
@raw_signature = <$fh>;
close($fh);
$signature = join(q{}, @raw_signature[4 .. 6]);
$signer = pgp_verify($signature, undef, IO::File->new("$data/message", 'r'));
is($signer,                $expected, 'DSAv4 sig from IO::File');
is(PGP::Sign::pgp_error(), q{},       '...with no errors');

# Check an ancient PGP 2.x signature.
open($fh, '<', "$data/message.rsa-pgp.sig");
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
