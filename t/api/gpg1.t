#!/usr/bin/perl
#
# Tests for the PGP::Sign object-oriented interface with GnuPG v1.
#
# Copyright 2020 Russ Allbery <rra@cpan.org>
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

# Path to GnuPG v1.
my $PATH;

# Check that GnuPG is available.  If so, load the module and set the plan.
BEGIN {
    $PATH = 'gpg1';
    if (!can_run('gpg1')) {
        if (gpg_is_gpg1()) {
            $PATH = 'gpg';
        } else {
            plan skip_all => 'gpg1 binary not available';
        }
    }
    if (!gpg_is_new_enough($PATH)) {
        plan skip_all => 'gpg binary is older than 1.4.20 or 2.1.23';
    }
    plan tests => 7;
    use_ok('PGP::Sign');
}

# Locate our test data directory for later use.
my $data = 't/data';

# Open and load our data file.  This is the sample data that we'll be signing
# and checking signatures against.
open(my $fh, '<', "$data/message");
my @data = <$fh>;
close($fh);

# The key ID and pass phrase to use for testing.
my $keyid = 'testing';
my $passphrase = 'testing';

# Build the signer object with default parameters.
my $signer = PGP::Sign->new(
    {
        home => File::Spec->catdir($data, 'gnupg1'),
        path => $PATH,
        style => 'GPG1',
    },
);

# Check a valid signature.
my $signature = $signer->sign($keyid, $passphrase, @data);
ok($signature, 'Signature is not undef');
is($keyid, $signer->verify($signature, @data), 'Signature verifies');

# Check a failed signature by adding some nonsense.
is(
    q{},
    $signer->verify($signature, @data, 'xyzzy'),
    'Signature does not verify with added nonsense',
);

# Avoid test warnings about using my obsolete address.  For better or worse,
# this was the UID used to generate older signatures, and I don't want to
# regenerate them since the point of these tests is to check signatures
# generated by obsolete versions.
my $expected = 'Russ Allbery <rra@' . 'stanford.edu>';

# Check an external version three DSA signature with data from an array ref.
open($fh, '<', "$data/message.dsa-v3.asc");
my @raw_signature = <$fh>;
close($fh);
$signature = join(q{}, @raw_signature[4 .. 6]);
is($expected, $signer->verify($signature, \@data), 'DSAv3 sig from array ref');

# Check an external version four DSA signature from an IO::Handle.
open($fh, '<', "$data/message.dsa-v4.asc");
@raw_signature = <$fh>;
close($fh);
$signature = join(q{}, @raw_signature[4 .. 6]);
my $result = $signer->verify($signature, IO::File->new("$data/message", 'r'));
is($result, $expected, 'DSAv4 sig from IO::File');

# Check an ancient PGP 2.x signature.
open($fh, '<', "$data/message.rsa-pgp.sig");
@raw_signature = <$fh>;
close($fh);
$signature = join(q{}, @raw_signature[3 .. 6]);
is(
    'R. Russell Allbery <eagle@windlord.stanford.edu>',
    $signer->verify($signature, \@data),
    'PGP sig from array ref',
);
