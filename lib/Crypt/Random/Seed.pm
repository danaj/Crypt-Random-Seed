package Crypt::Random::Seed;
use strict;
use warnings;
use Fcntl;
use Carp qw/carp croak/;

BEGIN {
  $Crypt::Random::Seed::AUTHORITY = 'cpan:DANAJ';
  $Crypt::Random::Seed::VERSION = '0.01';
}

use base qw( Exporter );
our @EXPORT_OK = qw( );
our %EXPORT_TAGS = (all => [ @EXPORT_OK ]);
our @EXPORT = qw( );  # nothing by default

# This is just used to keep track of the pre-defined names, so nobody can
# define a user method with this name.
my %defined_methods = (
  'CryptGenRandom' => 1,
  'RtlGenRand'     => 1,
  '/dev/random'    => 1,
  '/dev/urandom'   => 1,
  'TESHA2'         => 1,
);

sub new {
  my ($class, %params) = @_;
  my $self = {};

  if (defined $params{Source}) {
    if (ref($params{Source}) eq 'CODE') {
      $self->{Name}      = 'User';
      $self->{SourceSub} = $params{Source};
      # We don't know if it is blocking or strong, assume neither
      $self->{Blocking} = 0;
      $self->{Strong} = 0;
    } elsif (ref($params{Source}) eq 'ARRAY') {
      ($self->{Name}, $self->{SourceSub}, $self->{Blocking}, $self->{Strong})
      = @{$params{Source}};
      # For sanity, don't let them redefine the standard names.
      croak "Invalid name: $self->{Name}.  Name reserved."
        if defined $defined_methods{$self->{Name}};
    } else {
      croak "Invalid 'Source'.  Should be code or array reference.";
    }
  } else {
    my @methodlist = (
       \&_try_win32,
       \&_try_dev_random,
       \&_try_dev_urandom,
       \&_try_tesha2,
    );

    my %whitelist;
    my $have_whitelist = 0;
    if (defined $params{Only}) {
      croak "Parameter 'Only' must be an array ref" unless ref($params{Only}) eq 'ARRAY';
      $have_whitelist = 1;
      $whitelist{$_} = 1 for @{$params{Only}};
      if ($whitelist{'Win32'}) {
        $whitelist{'CryptGenRandom'} = 1;
        $whitelist{'RtlGenRand'} = 1;
      }
    }
    my %blacklist;
    if (defined $params{Never}) {
      croak "Parameter 'Never' must be an array ref" unless ref($params{Never}) eq 'ARRAY';
      $blacklist{$_} = 1 for @{$params{Never}};
      if ($blacklist{'Win32'}) {
        $blacklist{'CryptGenRandom'} = 1;
        $blacklist{'RtlGenRand'} = 1;
      }
    }

    foreach my $m (@methodlist) {
      my ($name, $rsub, $isblocking, $isstrong) = $m->();
      next unless defined $name;
      next if $params{NonBlocking} && $isblocking;
      next if !$isstrong && !$params{Weak};
      next if $blacklist{$name};
      next if $have_whitelist && !$whitelist{$name};
      $self->{Name}      = $name;
      $self->{SourceSub} = $rsub;
      $self->{Blocking}  = $isblocking;
      $self->{Strong}    = $isstrong;
      last;
    }
  }
  # Couldn't find anything appropriate
  return unless defined $self->{SourceSub};

  bless $self, $class;
  return $self;
}

# Nothing special to do on destroy
#sub DESTROY {
#  my $self = shift;
#  delete $self->{$_} for keys $self;
#  return;
#}

sub name {
  my $self = shift;
  return $self->{Name};
}
sub is_blocking {
  my $self = shift;
  return $self->{Blocking};
}
sub is_strong {
  my $self = shift;
  return $self->{Strong};
}
sub random_bytes {
  my ($self, $nbytes) = @_;
  return '' unless defined $nbytes && int($nbytes) > 0;
  my $rsub = $self->{SourceSub};
  return unless defined $rsub;
  return $rsub->(int($nbytes));
}
sub random_values {
  my ($self, $nvalues) = @_;
  return unless defined $nvalues && int($nvalues) > 0;
  my $rsub = $self->{SourceSub};
  return unless defined $rsub;
  return unpack( 'L*', $rsub->(4 * int($nvalues)) );
}


sub _try_tesha2 {
  eval { require Crypt::Random::TESHA2; Crypt::Random::TESHA2->import(); 1; }
  or return;
  my $isstrong = Crypt::Random::TESHA2::is_strong();
  return ('TESHA2', \&Crypt::Random::TESHA2::random_bytes, 0, 1);
}

sub _try_dev_urandom {
  return unless -r "/dev/urandom";
  return ('/dev/urandom', sub { __read_file('/dev/urandom', @_); }, 0, 0);
}

sub _try_dev_random {
  return unless -r "/dev/random";
  # FreeBSD's /dev/random is 256-bit Yarrow non-blocking.
  # Is it 'strong'?  Debatable -- we'll say it is.
  my $blocking = ($^O eq 'freebsd') ? 0 : 1;
  return ('/dev/random', sub { __read_file('/dev/random', @_); }, $blocking, 1);
}

sub __read_file {
  my ($file, $nbytes) = @_;
  return unless defined $nbytes && $nbytes > 0;
  sysopen(my $fh, $file, O_RDONLY);
  my($s, $buffer, $nread) = ('', '', 0);
  while ($nread < $nbytes) {
    my $thisread = sysread $fh, $buffer, $nbytes-$nread;
    # Count EOF as an error.
    croak "Error reading $file: $!\n" unless defined $thisread && $thisread > 0;
    $s .= $buffer;
    $nread += length($buffer);
    #die unless $nread == length($s);  # assert
  }
  croak "Internal file read error: wanted $nbytes, read $nread"
      unless $nbytes == length($s);  # assert
  return $s;
}

# Most of this is taken without notice from Crypt::URandom 0.28 and
# Crypt::Random::Source::Strong::Win32 0.07.
# Kudos to David Dick and Max Kanat-Alexander for doing all the work.
#
# See some documentation here:
#   http://msdn.microsoft.com/en-us/library/aa379942.aspx
# where they note that the output of these is really a well seeded CSPRNG:
# either FIPS 186-2 (older) or AES-CTR (Vista SP1 and newer).

sub _try_win32 {
  return unless $^O eq 'MSWin32';
  # Cygwin has /dev/random at least as far back as 2000.
  eval { require Win32; require Win32::API; require Win32::API::Type; 1; }
  or return;

  my $CRYPT_SILENT      = 0x40;          # Never display a UI.
  my $PROV_RSA_FULL     = 1;             # Which service provider.
  my $VERIFY_CONTEXT    = 0xF0000000;    # Don't require existing keypairs.
  my $W2K_MAJOR_VERSION = 5;             # Windows 2000
  my $W2K_MINOR_VERSION = 0;

  my ($major, $minor) = (Win32::GetOSVersion())[1, 2];
  return if $major < $W2K_MAJOR_VERSION;

  if ($major == $W2K_MAJOR_VERSION && $minor == $W2K_MINOR_VERSION) {
    # We are Windows 2000.  Use the older CryptGenRandom interface.
    my $crypt_acquire_context_a =
              Win32::API->new( 'advapi32', 'CryptAcquireContextA', 'PPPNN',
                'I' );
    return unless defined $crypt_acquire_context_a;
    my $context = chr(0) x Win32::API::Type->sizeof('PULONG');
    my $result = $crypt_acquire_context_a->Call(
             $context, 0, 0, $PROV_RSA_FULL, $CRYPT_SILENT | $VERIFY_CONTEXT );
    return unless $result;
    my $pack_type = Win32::API::Type::packing('PULONG');
    $context = unpack $pack_type, $context;
    my $crypt_gen_random =
              Win32::API->new( 'advapi32', 'CryptGenRandom', 'NNP', 'I' );
    return unless defined $crypt_gen_random;
    return ('CryptGenRandom',
            sub {
              my $nbytes = shift;
              my $buffer = chr(0) x $nbytes;
              my $result = $crypt_gen_random->Call($context, $nbytes, $buffer);
              croak "CryptGenRandom failed: $^E" unless $result;
              return $buffer;
            },
            0, 1);  # Assume non-blocking and strong
  } else {
    my $rtlgenrand = Win32::API->new( 'advapi32', <<'_RTLGENRANDOM_PROTO_');
INT SystemFunction036(
  PVOID RandomBuffer,
  ULONG RandomBufferLength
)
_RTLGENRANDOM_PROTO_
    return unless defined $rtlgenrand;
    return ('RtlGenRand',
            sub {
              my $nbytes = shift;
              my $buffer = chr(0) x $nbytes;
              my $result = $rtlgenrand->Call($buffer, $nbytes);
              croak "RtlGenRand failed: $^E" unless $result;
              return $buffer;
            },
            0, 1);  # Assume non-blocking and strong
  }
  return;
}

1;

__END__

# ABSTRACT: Simple method to get strong randomness

=pod

=head1 NAME

Crypt::Random::Seed - Simple method to get strong randomness


=head1 VERSION

Version 0.01


=head1 SYNOPSIS

  use Crypt::Random::Seed;

  my $source = new Crypt::Random::Seed;
  die "No strong sources exist" unless defined $source;
  my $seed_string = $source->random_bytes(4);
  my @seed_values = $source->random_values(4);

  # Allow weak sources, in case nothing strong is available
  my $maybe_weak_source = Crypt::Random::Seed( Weak=>1 );

  # Only non-blocking sources
  my $nonblocking_source = Crypt::Random::Seed( NonBlocking=>1 );

  # Blacklist sources (never choose the listed sources)
  my $nowin32_source = Crypt::Random::Seed( Never=>['Win32'] );

  # Whitelist sources (only choose from these sources)
  my $devr_source = Crypt::Random::Seed( Only=>['TESHA2'] );

  # Supply a custom source
  my $user_source = Crypt::Random::Seed( Source=>sub { egd(shift) } );
  # Or supply a list of [name, sub, is_blocking, is_strong]
  $user_source = Crypt::Random::Seed( Source=>['egd',sub {egd(shift)},0,1] );

  # Given a source there are a few things we can do:
  say "My randomness source is ", $source->name();
  say "I am a blocking source" if $source->is_blocking();
  say "I am a strong randomness source" if $source->is_strong()
  say "Four 8-bit numbers:",
      join(",", map { ord $source->random_bytes(1) } 1..4);'
  say "Four 32-bit numbers:", join(",", $source->random_values(4));


=head1 DESCRIPTION

A simple mechanism to get strong randomness.  The main purpose of this
module is to provide a simple way to generate a seed for a PRNG such as
L<Math::Random::ISAAC>, or for use in cryptographic key generation.  Flags
for accepting weak sources or requiring nonblocking sources are given, as
well as a very simple method for plugging in a source.

The randomness sources used are, in order:

=over 4

=item Win32 Crypto API.  This will use C<CryptGenRandom> on Windows 2000
      and C<RtlGenRand> on Windows XP and newer.  According to MSDN, these
      are well-seeded CSPRNGs (FIPS 186-2 or AES-CTR), so should
      be non-blocking.

=item /dev/random.  The strong source of randomness on most UNIX-like systems.
      Cygwin uses this, though it maps to the Win32 API.  On almost all
      systems this is a blocking source of randomness -- if it runs out of
      estimated entropy, it will hang until more has come into the system.
      If this is an issue, which it often is on embedded devices, running a
      tool such as L<HAVEGED|http://www.issihosts.com/haveged/> or
      L<EGD|http://egd.sourceforge.net/> will help immensely.

=item /dev/urandom.  A nonblocking source of randomness that we label as
      weak, since it will continue providing output even if the entropy has
      been exhausted.

=item L<Crypt::Random::TESHA2>, a module that generates random bytes from
      an entropy pool fed with timer/scheduler variations.  Measurements and
      tests are performed on installation to determine whether the source is
      considered strong or weak.  This is entirely in portable userspace,
      which is good for ease of use, but really requires user verification
      that it is working as expected if we expect it to be strong.  The
      concept is similar to L<Math::TrulyRandom> though updated to something
      closer to what TrueRand 2.1 does vs. the obsolete version 1 that
      L<Math::TrulyRandom> implements.  It is very slow and has wide speed
      variability across platforms : I've seen numbers ranging from 40 to
      150,000 bits per second.

=back

A source can also be supplied in the constructor.  Each of these sources will
have its debatable points about perceived strength.  E.g. Why is /dev/urandom
considered weak while Win32 is strong?  Can any userspace method such as
TrueRand or TESHA2 be considered strong?


=head1 CONSTRUCTOR

The constructor with no arguments will find the first strong source in its
fixed list and return an object that performs the defined methods.  This
will mean Win32, /dev/random, and TESHA2 (if it was considered strong on this
platform).  If no strong sources could be found (quite unusual) then the
returned value will be undef.

Optional parameters are passed in as a hash and may be mixed.

=head2 Weak => I<boolean>

Weak sources are also allowed.  This means /dev/urandom will be checked right
after /dev/random, and TESHA2 will be allowed even if it was considered weak
on this system.  If this option is specified, a source should always be
available.  Note that strong sources are still preferred.

=head2 NonBlocking => I<boolean>

Only non-blocking sources will be allowed.  In practice this means /dev/random
will not be chosen (except on FreeBSD where it is non-blocking).

=head2 Only => [I<list of strings>]

Takes an array reference containing one or more string source names.  No
source whose name does not match one of these strings will be chosen.  The
string 'Win32' will match either of the Win32 sources.

=head2 Never => [I<list of strings>]

Takes an array reference containing one or more string source names.  No
source whose name matches one of these strings will be chosen.  The string
'Win32' will match either of the Win32 sources.

=head2 Source => sub { I<...> }

Uses the given anonymous subroutine as the generator.  The subroutine will
be given an integer (the argument to C<random_bytes>) and should return
random data in a string of the given length.  For the purposes of the other
object methods, the returned object will have the name 'User', and be
considered non-blocking and non-strong.

=head2 Source => ['I<name>', sub { I<...> }, I<is_blocking>, I<is_strong>]

Similar to the simpler source routine, but also allows the other source
parameters to be defined.  The name may not be one of the standard names
listed in the L</"name"> section.


=head1 METHODS

=head2 random_bytes($n)

Takes an integer and returns a string of that size filled with random data.
Returns an empty string if the argument is not defined or is not more than
zero.

=head2 random_values($n)

Takes an integer and returns an array of that many random 32-bit values.
Returns an empty array if the argument is not defined or is not more than
zero.

=head2 name

Returns the text name of the random source.  This will be one of:
C<User> for user defined,
C<CryptGenRandom> for Windows 2000 Crypto API,
C<RtlGenRand> for Windows XP and newer Crypto API,
C</dev/random> for the UNIX-like strong randomness source,
C</dev/urandom> for the UNIX-like non-blocking randomness source,
C<TESHA2> for the userspace entropy method.  Other methods may be supported
in the future.  User supplied sources may be named anything other than one
of the defined names.

=head2 is_strong

Returns 1 or 0 indicating whether the source is considered a strong
source of randomness.

=head2 is_blocking

Returns 1 or 0 indicating whether the source can block on read.  Be aware
that even if a source doesn't block, it may be extremely slow.


=head1 AUTHORS

Dana Jacobsen E<lt>dana@acm.orgE<gt>


=head1 ACKNOWLEDGEMENTS

To the best of my knowledge, Max Kanat-Alexander was the original author of
the Perl code that uses the Win32 API.  I used his code as a reference.

David Oswald gave me a lot of help with API discussions and code reviews.


=head1 SEE ALSO

The first question one may ask is "Why yet another module of this type?"
None of the modules on CPAN quite fit my needs, hence this.  Some alternatives:

=head2 L<Math::Random::Source>

A comprehensive system using multiple plugins.  It's has a nice API, but
uses L<Any::Moose> which means you're loading up Moose or Mouse just to
read a few bytes from /dev/random.  It also has a very long dependency chain,
with on the order of 40 modules being installed as prerequisites (depending
of course on whether you use any of them on other projects).  Lastly, it
requires at least Perl 5.8, which may or may not matter to you.  But it
matters to some other module builders who end up with the restriction in
their modules.

=head2 L<Crypt::URandom>

A great little module that is almost what I was looking for.
L<Crypt::Random::Seed> will act the same if given the constructor:

  my $source = Crypt::Random::Seed->new(
     Weak => 1, NonBlocking => 1,
     Only => [qw(/dev/random /dev/urandom Win32)]
  );
  croak "No randomness source available" unless defined $source;

Or you can leave out the C<Only> and have TESHA2 as a backup.

=head2 L<Crypt::Random>

Requires L<Math::Pari> which makes it unacceptable in some environments.
Has more features (numbers in arbitrary bigint intervals or bit sizes).
L<Crypt::Random::Seed> is taking a simpler approach, just handling returning
octets and letting upstream modules handle the rest.

=head2 Upstream modules

Some modules that could build on top of this include
L<Bytes::Random::Secure>,
L<Math::Random::ISAAC>,
and L<Math::Random::Secure>,
to name a few.


=head1 COPYRIGHT

Copyright 2013 by Dana Jacobsen E<lt>dana@acm.orgE<gt>

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

The software is provided "AS IS", without warranty of any kind, express or
implied, including but not limited to the warranties of merchantability,
fitness for a particular purpose and noninfringement. In no event shall the
authors or copyright holders be liable for any claim, damages or other
liability, whether in an action of contract, tort or otherwise, arising from,
out of or in connection with the software or the use or other dealings in
the software.

=cut
