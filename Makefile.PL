# Makefile.PL for PGP::Sign module  -*- perl -*-
# $Id$
use ExtUtils::MakeMaker;
WriteMakefile (
    NAME         => 'PGP::Sign',
    DISTNAME     => 'PGP-Sign',
    ($] >= 5.005 ?
     (ABSTRACT   => 'Create and check PGP signatures, securely',
      AUTHOR     => 'Russ Allbery (rra@stanford.edu)') : ()),
    MAN3PODS     => { 'PGP/Sign.pm' => '$(INST_MAN3DIR)/PGP::Sign.3' },
    PL_FILES     => { 'makepm.PL' => 'PGP/Sign.pm' },
    PM           => { 'PGP/Sign.pm' => '$(INST_LIBDIR)/Sign.pm' },
    VERSION_FROM => 'VERSION.pm',
    dist         => { COMPRESS => 'gzip', SUFFIX => 'gz' },
    realclean    => { FILES => 'PGP/Sign.pm' }
);
