# Test suite for the PGP::Sign Perl module.  Before 'make install' is
# performed, this script should be runnable with 'make test'.  After 'make
# install', it should work as 'perl test.pl'.

# Locate our test data directory for later use.
my $data;
for (qw(./data ./t/data ../t/data)) { $data = $_ if -d $_ }
unless ($data) { die "Cannot find PGP data directory\n" }
$PGP::Sign::PGPPATH = $data;

# Open and load our data file.  This is the sample data that we'll be
# signing and checking signatures against.
open (DATA, "$data/message") or die "Cannot open $data/message: $!\n";
@data = <DATA>;
close DATA;
    
# The key ID and pass phrase to use for testing.
my $keyid = 'test';
my $passphrase = 'testing';

# Print out the count of tests we'll be running.
BEGIN { $| = 1; print "1..12\n" }

# 1 (ensure module can load)
END   { print "not ok 1\n" unless $loaded }
use PGP::Sign;
$loaded = 1;
print "ok 1\n";

# 2 (generate signature)
my ($signature, $version) = pgp_sign ($keyid, $passphrase, @data);
print 'not ' if PGP::Sign::pgp_error;
print "ok 2\n";

# 3 (check signature)
my $signer = pgp_verify ($signature, $version, @data);
print 'not ' if ($signer ne 'test' || PGP::Sign::pgp_error);
print "ok 3\n";

# 4 (check signature w/o version, which shouldn't matter)
$signer = pgp_verify ($signature, undef, @data);
print 'not ' if ($signer ne 'test' || PGP::Sign::pgp_error);
print "ok 4\n";

# 5 (check failed signature)
$signer = pgp_verify ($signature, $version, @data, "xyzzy");
print 'not ' if ($signer ne '' || PGP::Sign::pgp_error);
print "ok 5\n";

# 6 (whitespace munging)
$PGP::Sign::MUNGE = 1;
my @munged = @data;
for (@munged) { s/\n/ \n/ }
($signature, $version) = pgp_sign ($keyid, $passphrase, @munged);
$PGP::Sign::MUNGE = 0;
print 'not ' if PGP::Sign::pgp_error;
print "ok 6\n";

# 7 (check a signature of munged data against the munged version)
$signer = pgp_verify ($signature, $version, @data);
print 'not ' if ($signer ne 'test' || PGP::Sign::pgp_error);
print "ok 7\n";

# 8 (check signature of munged data against unmunged data with MUNGE)
$PGP::Sign::MUNGE = 1;
$signer = pgp_verify ($signature, $version, @munged);
$PGP::Sign::MUNGE = 0;
print 'not ' if ($signer ne 'test' || PGP::Sign::pgp_error);
print "ok 8\n";

# 9 (check signature of munged data against unmunged data w/o MUNGE)
$signer = pgp_verify ($signature, $version, @munged);
print 'not ' if ($signer ne '' || PGP::Sign::pgp_error);
print "ok 9\n";

# 10 (take data from a code ref)
my $munger = sub { local $_ = shift @munged; s/ +$//; $_ };
$signature = pgp_sign ($keyid, $passphrase, $munger);
print 'not ' if PGP::Sign::pgp_error;
print "ok 10\n";

# 11 (check the resulting signature)
$signer = pgp_verify ($signature, undef, @data);
my @errors = PGP::Sign::pgp_error;
print 'not ' if ($signer ne 'test' || @errors);
warn @errors if @errors;
print "ok 11\n";

# 12 (check an external signature)
if (open (SIG, "$data/message.asc") && open (DATA, "$data/message")) {
    my @signature = <SIG>;
    close SIG;
    $signature = join ('', @signature[3..6]);
    $signer = pgp_verify ($signature, undef, \*DATA);
    @errors = PGP::Sign::pgp_error;
    if ($signer ne 'R. Russell Allbery <rra@stanford.edu>'
        || PGP::Sign::pgp_error) {
        print 'not ';
    }
} else {
    print 'not ';
}
print "ok 12\n";
