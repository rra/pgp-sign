# makepm.PL -- Builds PGP/Sign.pm from PGP/Sign.in.  -*- perl -*-
# $Id$
#
# The main reason why we have this script is to figure out where PGP is on
# the system and code that into PGP::Sign before we install the module.
# While we're at it, we also pull in our version number from a separate file
# to give us some flexibility in release numbering.

# First, grab the line to set the version number, since we'll need to
# substitute that in to PGP/Sign.pm when we build it.  It's the second line
# of VERSION.pm.
open (VERSION, 'VERSION.pm') or die "Cannot open VERSION.pm: $!\n";
<VERSION>;
my $version = <VERSION>;
close VERSION;

# Search for PGP.  We start by searching the user's PATH, and then check a
# few other standard directories.  When we find something that looks like
# PGP, we run it to see if that's really what it is and to make sure that
# it's the right version.
sub find_pgp {
    my @directories = map { s/^$/./; $_ } split (':', $ENV{PATH});
    push (@directories, qw(/usr/local/bin /usr/bin /opt/bin));
    my @programs = qw(pgp pgp2 pgp26 pgp263 pgp262);
    my $directory;
    for $directory (@directories) {
        next unless -d $directory;
        for (@programs) {
            my $program = "$directory/$_";
            next unless -x $program;
            next unless (`$program 2>&1` =~ /Pretty Good Privacy.*2\./);
            return $program;
        }
    }
}

# Used for heredocs to make them more readable.
sub unquote { my ($string) = @_; $string =~ s/^: {0,7}//gm; $string }

# Do the search, and prompt based on the results.
my $pgp = find_pgp;
print unquote (<<"EOM");
:
:       PGP::Sign needs to know the path to PGP; this path will be encoded
:       in the installed module as the default path to PGP (it can be
:       overridden at runtime).  Please enter the full path to the PGP
:       binary (version 2, preferrably 2.6.2 or 2.6.3, not version 5) below
:       or just press Enter if the guess is correct.
:
EOM
print 'Path to PGP [' . ($pgp || '/usr/local/bin/pgp') . ']: ';
my $input = <STDIN>;
chomp $input;
$pgp = $pgp || $input || '/usr/local/bin/pgp';
print "\n";

# Now, open our input file and create our output file, and then do the
# necessary substitutions.
open (IN, 'PGP/Sign.in') or die "Cannot open PGP/Sign.in: $!\n";
open (OUT, '> PGP/Sign.pm') or die "Cannot open PGP/Sign.pm: $!\n";
while (<IN>) {
    if (/^\# @@ VERSION/) { print OUT $version }
    elsif (/^\# @@ PGP/)  { print OUT q($PGP = ') . $pgp . q(';) . "\n" }
    else                  { print OUT }
}
close OUT;
close IN;
