# Makefile.PL for PGP::Sign module
# $Id$
use ExtUtils::MakeMaker;
WriteMakefile (NAME         => 'PGP::Sign',
	       DISTNAME     => 'PGP-Sign',
               VERSION_FROM => 'PGP/Sign.pm',
	       dist         => { COMPRESS => 'gzip', SUFFIX => 'gz' });
