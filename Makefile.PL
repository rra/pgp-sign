# Makefile.PL for PGP::Sign module  -*- perl -*-
# $Id$
use ExtUtils::MakeMaker;

# This is ugly hack number one.  We want people to be able to specify the
# path to PGP on the command line when they run perl Makefile.PL, so we hack
# in a little bit of options processing to find and take the PGP setting.
# We have to remove it from @ARGV before calling WriteMakefile, or MakeMaker
# will complain about it.
my $makepm = 'makepm.PL';
@ARGV = map {
    if (/^PGP=(.*)/) {
        $makepm .= ' ' . $1;
        ();
    } else {
        $_;
    }
} @ARGV;

# This is ugly hack number two.  We need to pass the path to PGP along to
# makepm.PL.  If we do, though, it also puts the path to PGP in the Makefile
# dependencies line, which is rather annoying and not what we want.  So this
# hack overrides the MakeMaker method that builds that line and strips off
# the path to PGP.  This assumes that the second word after the :: of the
# make rule is the path to PGP, which *appears* to be safe across all
# platforms at least currently.
sub MY::processPL {
    package MY;
    my $inherited = shift->SUPER::processPL (@_);
    $inherited =~ s/ :: (\S+) (\S+)/ :: $1/;
    $inherited;
}

# Now actually build the Makefile.
WriteMakefile (
    NAME         => 'PGP::Sign',
    DISTNAME     => 'PGP-Sign',
    ($] >= 5.005 ?
     (ABSTRACT   => 'Create and check PGP signatures, securely',
      AUTHOR     => 'Russ Allbery (rra@stanford.edu)') : ()),
    MAN3PODS     => { 'PGP/Sign.pm' => '$(INST_MAN3DIR)/PGP::Sign.3' },
    PL_FILES     => { $makepm => 'PGP/Sign.pm' },
    PM           => { 'PGP/Sign.pm' => '$(INST_LIBDIR)/Sign.pm' },
    VERSION_FROM => 'VERSION.pm',
    dist         => { COMPRESS => 'gzip', SUFFIX => 'gz' },
    realclean    => { FILES => 'PGP/Sign.pm' }
);
