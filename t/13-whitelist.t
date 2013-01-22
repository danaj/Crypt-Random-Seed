#!/usr/bin/env perl
use strict;
use warnings;
use Crypt::Random::Seed;

use Test::More  tests => 4;

# Expect croak if Only isn't an array reference
ok(!eval {Crypt::Random::Seed->new(Only=>0);}, "Only with non-array reference croaks");

my $source = Crypt::Random::Seed->new(Only=>['TESHA2']);
ok(defined $source, "Only=>[TESHA2] returned something");
like($source->name(), qr/^TESHA2/, "Only=>[TESHA2] returned TESHA2");

my $source2 = Crypt::Random::Seed->new(Only=>[]);
ok(!defined $source2, "An empty whitelist means no object returned");
