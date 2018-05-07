#!/usr/bin/perl
#
# Build script for the PGP::Sign distribution.
#
# Copyright 2018 Russ Allbery <rra@cpan.org>
#
# This program is free software; you may redistribute it and/or modify it
# under the same terms as Perl itself.
#
# SPDX-License-Identifier: GPL-1.0-or-later OR Artistic-1.0-Perl

use 5.010;
use autodie;
use strict;
use warnings;

use Module::Build;

# Basic package configuration.
my $build = Module::Build->new(
    module_name          => 'PGP::Sign',
    dist_author          => 'Russ Allbery <rra@cpan.org>',
    license              => 'perl',
    add_to_cleanup       => [qw(t/data/random_seed t/data/trustdb.gpg)],
    recursive_test_files => 1,

    # Other package relationships.
    configure_requires => { 'Module::Build' => 0.28    },
    requires           => { 'perl'          => '5.010' },
);

# Generate the build script.
$build->create_build_script();
