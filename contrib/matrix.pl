#!/usr/bin/env perl

# matrix.pl - displays dbeacon dump information in a matrix et al.
#
# Originally by Hoerdt Mickaël
# Modifications by Hugo Santos

# change this filename to your dump file
my $dump_file = "/home/hugo/work/mcast/dbeacon/dump2.xml";

# Program code follows

use CGI;

use Graph::Directed;
use XML::Parser;
use strict;

my $page = new CGI;

print $page->header;

my $attname = $page->param('att');
if ($attname eq "") {
	$attname = "ttl";
}

my $sessiongroup;

my $current_beacon;
my %adjacency_matrix;
my $parser;
my $g;

$g = new Graph::Directed;
# initialize parser and read the file
$parser = new XML::Parser( Style => 'Tree' );
$parser->setHandlers(Start => \&start_handler);
my $tree = $parser->parsefile($dump_file);

my @V = $g->vertices();

print "<html>\n";

print "
<head>

<meta http-equiv=\"refresh\" content=\"60\" />

<style type=\"text/css\">
body {
	font-family: Verdana, Arial, Helvetica, sans-serif;
	font-size: 100%;
}

table#adj {
	text-align: center;
	border-spacing: 1px;
}
table#adj td.beacname {
	text-align: right;
}
table#adj td {
	padding: 2px;
}
table#adj td.adjacent {
	background-color: #96ef96;
}
table#adj td.blackhole {
	background-color: #000000;
}
table#adj td.noinfo {
	background-color: #ff0000;
}
table#adj td.corner {
	background-color: #dddddd;
}

table#beacs td {
	padding: 5px;
}

table#beacs td.name {
	border-left: 2px solid black;
}

table#beacs td.name, table#beacs td.addr, table#beacs td.admincontact, table#beacs td.age {
	border-right: 2px solid black;
}

table#beacs td.addr, table#beacs td.admincontact {
	font-family: Monospace;
}

</style>
</head>
";

print "<body>\n";

print "<h1>IPv6 Multicast Beacon</h1>\n";

my $now = localtime();

print "<h4>Current Server time is $now</h4>\n";

print "<h4>Current stats for $sessiongroup</h4>\n";

my $url = $page->script_name();

print "<p><b>Parameters:</b> [<a href=\"$url?att=ttl\">TTL</a>] [<a href=\"$url?att=loss\">Loss</a>] [<a href=\"$url?att=delay\">Delay</a>] [<a href=\"$url?att=jitter\">Jitter</a>]</p>\n";

print "<table border=\"0\" cellspacing=\"0\" cellpadding=\"0\" id=\"adj\">\n";

print "<tr>\n";
print "<td></td>";
my $c;
my $i = 1;
my @problematic = ();

foreach $c (@V) {
	if (scalar($g->edges($c)) ge 1) {
		print "<td>\n";
		print "<b>S$i</b>";
		print "</td>\n";
		$i++;
	} else {
		push(@problematic, $a);
	}
}
print "</tr>\n";

$i = 1;
foreach $a (@V) {
	if (scalar($g->edges($c)) ge 1) {
		print "<tr>";
		print "<td class=\"beacname\">";
		print "$a <b>R$i</b>";
		print "</td>";
		foreach $b (@V) {
			my $txt;
			my $tdclass = "blackhole";
			if ($g->has_edge($b, $a)) {
				$txt = $g->get_edge_attribute($b, $a, $attname);
				if ($txt eq "") {
					$txt = "N/A";
					$tdclass = "noinfo";
				} else {
					$tdclass = "adjacent";
				}
			} else {
				if ($a eq $b) {
					$tdclass = "corner";
				}
			}
			print "<td class=\"$tdclass\">$txt</td>";
		}
		print "<tr>";
		print "\n";
		$i++;
	}
}
print "</table>";

if (scalar(@problematic) ne 0) {
	print "<br /><br />\n";
	print "<h3>Beacons with no connectivity</h3>\n";
	print "<ul>\n";
	my $len = scalar(@problematic);
	for (my $j = 0; $j < $len; $j++) {
		my $prob = $problematic[$j];
		print "<li>$prob</li>\n";
	}
	print "</ul>\n";
}

print "<br /><br />\n";
print "<table cellspacing=\"0\" cellpadding=\"0\" id=\"beacs\">";
print "<tr><th>Beacon Name</th><th>Source Address/Port</th><th>Admin Contact</th><th>Age</th></tr>\n";

foreach $a (@V) {
	my $addr = $g->get_vertex_attribute($a, "addr");
	my $contact = $g->get_vertex_attribute($a, "contact");
	my $age = $g->get_vertex_attribute($a, "age");
	print "<tr><td class=\"name\">$a</td><td class=\"addr\">$addr</td><td class=\"admincontact\">$contact</td><td class=\"age\">$age secs</td></tr>\n";
}

print "</table>";

print "<br /><br />";

print "<p>If you wish to add a beacon to your site, you may use dbeacon with the following parameters:</p>\n";
print "<p><code>./dbeacon -P -n NAME -b $sessiongroup -a CONTACT</code></p>\n";

print "</body>";
print "</html>";

sub start_handler {
	my ($p, $tag, %atts) = @_;
	my $name;
	my $value;

	if ($tag eq "beacon") {
		my $fname;
		my $fadmin;
		my $faddr;
		my $fage;
		while (($name, $value) = each %atts) {
			if ($name eq "name") {
				$fname = $value;
			} elsif ($name eq "contact") {
				$fadmin = $value;
			} elsif ($name eq "addr") {
				$faddr = $value;
			} elsif ($name eq "age") {
				$fage = $value;
			} elsif ($name = "group") {
				$sessiongroup = $value;
			}
		}

		$current_beacon = $fname;

		if ($fname ne "") {
			$g->add_vertex($fname);
			$g->set_vertex_attribute($fname, "contact", $fadmin);
			$g->set_vertex_attribute($fname, "addr", $faddr);
			$g->set_vertex_attribute($fname, "age", $fage);
		}
	} elsif ($tag eq "source") {
		my $fname;
		my $fadmin;
		my $faddr;
		my $fttl = -1;
		my $floss = -1;
		my $fdelay = -1;
		my $fjitter = -1;
		while (($name, $value) = each %atts) {
			if ($name eq "name") {
				$fname = $value;
			} elsif ($name eq "contact") {
				$fadmin = $value;
			} elsif ($name eq "addr") {
				$faddr = $value;
			} elsif ($name eq "ttl") {
				$fttl = $value;
			} elsif ($name eq "loss") {
				$floss = $value;
			} elsif ($name eq "delay") {
				$fdelay = $value;
			} elsif ($name eq "jitter") {
				$fjitter = $value;
			}
		}

		if ($fname ne "") {
			$g->add_vertex($fname);
			$g->set_vertex_attribute($fname, "contact", $fadmin);
			$g->set_vertex_attribute($fname, "addr", $faddr);

			$g->add_edge($fname, $current_beacon);
			if ($fttl ge 0) {
				$g->set_edge_attribute($fname, $current_beacon, "ttl", $fttl);
			}
			if ($floss ge 0) {
				$g->set_edge_attribute($fname, $current_beacon, "loss", $floss);
			}
			if ($fdelay ge 0) {
				$g->set_edge_attribute($fname, $current_beacon, "delay", $fdelay);
			}
			if ($fjitter ge 0) {
				$g->set_edge_attribute($fname, $current_beacon, "jitter", $fjitter);
			}
		}
	}
}

