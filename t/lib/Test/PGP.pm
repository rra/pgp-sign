# Helper functions for PGP::Sign tests.
#
# SPDX-License-Identifier: GPL-1.0-or-later OR Artistic-1.0-Perl

package Test::PGP 1.00;

use 5.020;
use autodie;
use version;
use warnings;

use Exporter qw(import);
use IPC::Cmd qw(run);

our @EXPORT_OK = qw(gpg_is_gpg1 gpg2_is_new_enough);

# Test if the gpg binary found first on PATH is actually gpg1.
#
# Returns: 1 if so, undef if not or on any errors
sub gpg_is_gpg1 {
    my $output;
    if (!run(command => ['gpg', '--version'], buffer => \$output)) {
        return;
    }
    return $output =~ m{ ^ gpg [^\n]* \s 1 [.] }xms;
}

# Test if the GnuPG v2 binary is new enough to have the flags we expect.
#
# $path - Path to the GnuPG v2 binary
#
# Returns: 1 if so, undef if not or on any errors
sub gpg2_is_new_enough {
    my ($path) = @_;
    my $output;
    if (!run(command => [$path, '--version'], buffer => \$output)) {
        return;
    }
    if ($output =~ m{ ^ gpg [^\n] * \s (2 [.\d]+) }xms) {
        my $version = $1;
        return version->parse($version) >= version->parse('2.1.12');
    } else {
        warn "Cannot determine version of $path\n";
        return;
    }
}

1;
