#!/usr/bin/perl
#
# Test PGP::Sign in the presence of locale settings.
#
# This ensures that we're correctly using the machine-readable status API and
# not the output intended for humans.
#
# Copyright 1998-2001, 2004, 2007, 2018, 2020 Russ Allbery <rra@cpan.org>
#
# This program is free software; you may redistribute it and/or modify it
# under the same terms as Perl itself.
#
# SPDX-License-Identifier: GPL-1.0-or-later OR Artistic-1.0-Perl

use 5.010;
use autodie;
use strict;
use warnings;

use Test::More tests => 5;

BEGIN {
    use_ok('PGP::Sign', qw(pgp_sign pgp_verify pgp_error));
}

# Set the locale.  I use French for testing; this won't be a proper test
# unless the locale is available on the local system, so hopefully this will
# be a common one.
local $ENV{LC_ALL} = 'fr_FR';

# Locate our test data directory for later use.
my $data = 't/data';
$PGP::Sign::PGPPATH = $data;

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
isnt($signature, undef, 'Signature');
is(pgp_error(), q{}, '...with no errors');

# Check signature.
is(pgp_verify($signature, $version, @data), $keyid, 'Verify');
is(pgp_error(),                             q{},    '...with no errors');
