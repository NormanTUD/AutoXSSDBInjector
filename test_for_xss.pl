#!/usr/bin/perl

=head
IDEA:

This module allows the automatic insertion of values into a database for
finding possible XSS-flaws on your website.

It works by connecting to a specific database, going through the tables and
inserting possible XSS-codes into potentially vulnerable columns (i.e. varchar,
blob, ...). You then need to surf the website and look for codes popping up.

Beware: disable CSP on your website/webserver before doing so, otherwise, you
won't see popups like alert(1) that are inserted by this script.

The general idea is that user-input gets into the database and is then read-out
again. If there is no security mechanism, users may be able to print their code
on your website.

USAGE:

See the script below.

=cut

use strict;
use warnings;
use lib '.';
use DBAnalysis;

my ($dbname, $password, $copyfrom) = ();

my $dbanalysis = DBAnalysis->new(
	dbname => $dbname, # The database you want to work on
	username => "root",  # The username of your local database
	host => "localhost", # The host of your local database
	password => $password,  # The password for your database
	copyfrom => $copyfrom,	# If enabled, this copies the database $copyfrom to $dbname, so the original database doesn't get altered
	number_of_injections => 2, # The number of injections that should be tried
	debug => 1 # Enables debug-output
);

$dbanalysis->analyze_db(); # Automatically searches vulnerable columns and inserts possibe XSS-values in them
