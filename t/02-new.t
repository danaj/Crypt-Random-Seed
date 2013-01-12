#!/usr/bin/env perl
use strict;
use warnings;
use Crypt::Random::Seed;

use Test::More  tests => 1;

my $source = new Crypt::Random::Seed;
isa_ok $source, 'Crypt::Random::Seed';
