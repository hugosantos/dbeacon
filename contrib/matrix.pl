#!/usr/bin/env perl

# matrix.pl - displays dbeacon dump information in a matrix et al.
#
# Originally by Hoerdt Mickaël
# Modifications by Hugo Santos

# change this filename to your dump file
my $dump_file = "/home/hugo/work/mcast/dbeacon/dump.xml";

# Program code follows

use CGI;

use Graph::Directed;
use XML::Parser;
use Switch;
use integer;
use strict;

my $page = new CGI;

print $page->header;

my $attname = $page->param('att');
if (not $attname) {
	$attname = "ttl";
}

my $sessiongroup;
my $ssm_sessiongroup;

my $current_beacon;
my $current_source;
my %adjacency_matrix;
my $parser;
my $g;

$g = new Graph::Directed;
# initialize parser and read the file
$parser = new XML::Parser(Style => 'Tree');
$parser->setHandlers(Start => \&start_handler);
my $tree = $parser->parsefile($dump_file);

print "<html>\n";

print "
<head>

<meta http-equiv=\"refresh\" content=\"60\" />

<style type=\"text/css\">
body {
	font-family: Verdana, Arial, Helvetica, sans-serif;
	font-size: 100%;
}

table.adjr {
	text-align: center;
}
table.adjr td.beacname {
	text-align: right;
}
table.adjr td {
	padding: 3px;
	border-bottom: 0.1em solid white;
}
table#adj td.adjacent, table#adj td.ssmadjacent {
	background-color: #96ef96;
	width: 20px;
}

table#adj td.blackhole {
	background-color: #000000;
}
table#adj td.noinfo {
	background-color: #ff0000;
}
table#adj td.noasminfo, table#adj td.nossminfo {
	background-color: #b6ffb6;
	width: 20px;
}
table#adj td.corner {
	background-color: #dddddd;
}

table#adj td.adjacent {
	border-right: 0.075em solid white;
}

table#adj td.blackhole, table#adj td.noinfo, table#adj td.ssmadjacent, table#adj td.corner, table#adj td.nossminfo {
	border-right: 0.2em solid white;
}

table#adjname td.addr, table#adjname td.admincontact, table#adjname td.age, table#adjname td.urls {
	background-color: #eeeeee;
	border-right: 0.2em solid white;
}
table#adjname td.age {
	font-size: 80%;
}

.addr, .admincontact {
	font-family: Monospace;
}

.beacon {
	font-style: italic;
}

</style>
</head>
";

print "<body>\n";

print "<h1>IPv6 Multicast Beacon</h1>\n";

my $now = localtime();

print "<h4>Current Server time is $now</h4>\n";

print "<h4>Current stats for $sessiongroup";
if ($ssm_sessiongroup) {
	print " (SSM: $ssm_sessiongroup)";
}
print "</h4>\n";

switch ($attname)
{
  case "loss"	{ print "<h4>Current view is Loss in %</h4>\n" }
  case "delay"	{ print "<h4>Current view is Delay in ms</h4>\n" }
  case "jitter"	{ print "<h4>Current view is Jitter in ms</h4>\n" }
  else		{ $attname = "ttl"; print "<h4>Current view is TTL in number of hops</h4>\n" }
}

my $url = $page->script_name();

print "<p><b>Parameters:</b> [<a href=\"$url?att=ttl\">TTL</a>] [<a href=\"$url?att=loss\">Loss</a>] [<a href=\"$url?att=delay\">Delay</a>] [<a href=\"$url?att=jitter\">Jitter</a>]</p>\n";

print "<table border=\"0\" cellspacing=\"0\" cellpadding=\"0\" class=\"adjr\" id=\"adj\">\n";

print "<tr>";
print "<td></td>";
my $c;
my $i = 1;
my @problematic = ();
my @warmingup = ();

my @V = $g->vertices();

foreach $c (@V) {
	my $goodedge = $g->get_vertex_attribute($c, "goodedge");
	my $age = $g->get_vertex_attribute($c, "age");

	if (($age ne "") and ($age < 30)) {
		push (@warmingup, $c);
	} elsif (not $goodedge) {
		push (@problematic, $c);
	} else {
		print "<td colspan=\"2\"><b>S$i</b></td>";

		$g->set_vertex_attribute($c, "id", $i);

		$i++;
	}
}
print "</tr>\n";

foreach $a (@V) {
	my $id = $g->get_vertex_attribute($a, "id");
	if ($id >= 1) {
		print "<tr>";
		print "<td class=\"beacname\">";
		my $name = $g->get_vertex_attribute($a, "name");
		print "$name <b>R$id</b>";
		print "</td>";
		foreach $b (@V) {
			$id = $g->get_vertex_attribute($b, "id");
			if ($id >= 1) {
				if ($g->has_edge($b, $a)) {
					my $txt;
					my $txtssm;
					my $tdclass = "adjacent";
					my $tdclasssm = "ssmadjacent";
					$txt = $g->get_edge_attribute($b, $a, $attname);
					$txtssm = $g->get_edge_attribute($b, $a, "ssm_" . $attname);
					if (($txt eq "") and ($txtssm eq "")) {
						print "<td colspan=\"2\" class=\"noinfo\">N/A</td>";
					} else {
						if ($txt eq "") {
							$txt = "-";
							$tdclass = "noasminfo";
						} elsif ($txtssm eq "") {
							$txtssm = "-";
							$tdclasssm = "nossminfo";
						}
						print "<td class=\"$tdclass\">$txt</td><td class=\"$tdclasssm\">$txtssm</td>";
					}
				} else {
					if ($a eq $b) {
						print "<td colspan=\"2\" class=\"corner\">&nbsp;</td>";
					} else {
						print "<td colspan=\"2\" class=\"blackhole\">&nbsp;</td>";
					}
				}
			}
		}
		print "</tr>\n";
	}
}
print "</table>\n";

print "<br />\n";

print "<table border=\"0\" cellspacing=\"0\" cellpadding=\"0\" class=\"adjr\" id=\"adjname\">\n";

print "<tr><td></td><td><b>Age</b></td><td><b>Source Address/Port</b></td><td><b>Admin Contact</b></td><td><b>W</b></td></tr>";
foreach $a (@V) {
	my $id = $g->get_vertex_attribute($a, "id");
	if ($id >= 1) {
		print "<tr>";
		print "<td class=\"beacname\">";
		my $name = $g->get_vertex_attribute($a, "name");
		my $contact = $g->get_vertex_attribute($a, "contact");
		my $age = $g->get_vertex_attribute($a, "age");
		if (not $age) {
			$age = "-";
		} else {
			$age = format_date($age);
		}
		print "$name <b>R$id</b>";
		print "</td>";
		print "<td class=\"age\">$age</td><td class=\"addr\">$a</td><td class=\"admincontact\">$contact</td>";

		my $urls;
		if ($g->has_vertex_attribute($a, "url_generic")) {
			$urls .= " <a href=\"" . $g->get_vertex_attribute($a, "url_generic") . "\">W</a>";
		}
		if ($g->has_vertex_attribute($a, "url_lg")) {
			$urls .= " <a href=\"" . $g->get_vertex_attribute($a, "url_lg") . "\">L</a>";
		}
		if ($g->has_vertex_attribute($a, "url_matrix")) {
			$urls .= " <a href=\"" . $g->get_vertex_attribute($a, "url_matrix") . "\">M</a>";
		}

		if ($urls eq "") {
			$urls = "-";
		}

		print "<td class=\"urls\">$urls</td>";
		print "</tr>\n";
	}
}
print "</table>\n";

print "<br />\n";

if (scalar(@warmingup) > 0) {
	print "<h3>Beacons warming up (age < 30 secs)</h3>\n";
	print "<ul>\n";
	foreach $a (@warmingup) {
		my $name = $g->get_vertex_attribute($a, "name");
		my $contact = $g->get_vertex_attribute($a, "contact");
		print "<li>$a";
		if ($name) {
			print " ($name, $contact)";
		}
		print "</li>\n";
	}
	print "</ul>\n";
}

if (scalar(@problematic) ne 0) {
	print "<h3>Beacons with no connectivity</h3>\n";
	print "<ul>\n";
	my $len = scalar(@problematic);
	for (my $j = 0; $j < $len; $j++) {
		my $prob = $problematic[$j];

		my $name = $g->get_vertex_attribute($prob, "name");
		my $admin = $g->get_vertex_attribute($prob, "contact");

		my @neighs = $g->neighbours($prob);

		print "<li>$prob";
		if ($name) {
			print " ($name, $admin)";
		}

		my $ned = scalar(@neighs);
		my $k = $ned;
		if ($k > 3) {
			$k = 3;
		}

		print "<ul>Received from:<ul>";

		for (my $l = 0; $l < $k; $l++) {
			my $addr = $neighs[$l];
			$name = $g->get_vertex_attribute($addr, "name");
			print "<li><span class=\"beacon\">$addr";
			if ($name) {
				print " ($name)";
			}
			print "</span></li>";
		}

		if ($k < $ned) {
			print "<li>and others</li>";
		}

		print "</ul></ul></li>\n";
	}
	print "</ul>\n";
}

print "<p>If you wish to add a beacon to your site, you may use dbeacon with the following parameters:</p>\n";
print "<p><code>./dbeacon -n NAME -b $sessiongroup";
if ($ssm_sessiongroup) {
	print " -S $ssm_sessiongroup";
}
print " -a CONTACT</code></p>\n";

print "<hr />\n";
print "<small>matrix.pl - a tool for dynamic viewing of dbeacon information. by Hugo Santos and Hoerdt Mickaël</small>\n";

print "</body>";
print "</html>";

sub format_date {
	my $tm = shift;
	my $res;

	if ($tm > 86400) {
		my $days = $tm / 86400;
		$res .= " $days";
		$res .= "d";
		$tm = $tm % 86400;
	}

	if ($tm > 3600) {
		my $hours = $tm / 3600;
		$res .= " $hours";
		$res .= "h";
		$tm = $tm % 3600;
	}

	if ($tm > 60) {
		my $mins = $tm / 60;
		$res .= " $mins";
		$res .= "m";
		$tm = $tm % 60;
	}

	if ($tm > 0) {
		$res .= " $tm";
		$res .= "s";
	}

	return $res;
}

sub start_handler {
	my ($p, $tag, %atts) = @_;
	my $name;
	my $value;

	if ($tag eq "beacon") {
		if ($atts{"group"} ne "") {
			$sessiongroup = $atts{"group"};
		}
		if ($atts{"ssmgroup"} ne "") {
			$ssm_sessiongroup = $atts{"ssmgroup"};
		}
		if ($atts{"addr"} ne "") {
			$current_beacon = $atts{"addr"};
			$current_source = "";

			if (($atts{"name"} ne "") and ($atts{"age"} > 0)) {
				$g->add_vertex($current_beacon);
				$g->set_vertex_attribute($current_beacon, "name", $atts{"name"});
				$g->set_vertex_attribute($current_beacon, "contact", $atts{"contact"});
				$g->set_vertex_attribute($current_beacon, "age", $atts{"age"});
			}
		}
	} elsif ($tag eq "ssm") {
		if ($current_source ne "") {
			parse_stats($current_source, "ssm_", %atts);
		}
	} elsif ($tag eq "source") {
		if (($atts{"name"} ne "") and ($atts{"addr"} ne "")) {
			$current_source = $atts{"addr"};
			if (not $g->has_vertex($current_source)) {
				$g->add_vertex($current_source);

				$g->set_vertex_attribute($current_source, "name", $atts{"name"});
				$g->set_vertex_attribute($current_source, "contact", $atts{"contact"});
			}

			$g->add_edge($current_source, $current_beacon);

			parse_stats($current_source, "", %atts);
		}
	} elsif ($tag eq "website") {
		if ($atts{"type"} ne "" and $atts{"url"} ne "") {
			if ($current_source ne "") {
				$g->set_vertex_attribute($current_source, "url_" . $atts{"type"}, $atts{"url"});
			} else {
				$g->set_vertex_attribute($current_beacon, "url_" . $atts{"type"}, $atts{"url"});
			}
		}
	}
}

sub parse_stats {
	my ($addr, $prefix, %atts) = @_;

	if ($atts{"ttl"} ge 0) {
		$g->set_edge_attribute($addr, $current_beacon, $prefix . "ttl", $atts{"ttl"});
		my $val = $g->get_vertex_attribute($addr, "goodedge");
		$g->set_vertex_attribute($addr, "goodedge", $val + 1);
	}

	my @statsAtts = ("loss", "delay", "jitter");
	my $len = scalar(@statsAtts);

	for (my $j = 0; $j < $len; $j++) {
		if ($atts{$statsAtts[$j]} ge 0) {
			$g->set_edge_attribute($addr, $current_beacon, $prefix . $statsAtts[$j], $atts{$statsAtts[$j]});
		}
	}
}

