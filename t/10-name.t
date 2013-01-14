#!/usr/bin/env perl
use strict;
use warnings;
use Crypt::Random::Seed;

use Test::More  tests => 2;

my $source = Crypt::Random::Seed->new(Weak=>1);

my $name = $source->name();
diag "Method: $name";
ok(defined($name));
ok($name ne '');
