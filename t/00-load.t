#!perl -T

use Test::More tests => 1;

BEGIN {
	use_ok( 'WebService::RTMAgent' );
}

diag( "Testing WebService::RTMAgent $WebService::RTMAgent::VERSION, Perl $], $^X" );
