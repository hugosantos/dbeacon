#!/usr/bin/env perl

# matrix.pl - displays dbeacon dump information in a matrix et al.
#
# Originally by Hoerdt Mickaël
# Modifications by Hugo Santos

use CGI;
use Graph::Directed;
use XML::Parser;
use integer;
use strict;

my $default_hideinfo = 0;	# one of '0', '1'
my $default_what = "both";	# one of 'both', 'asm'

# change this filename to your dump file
my $dump_file = "/home/hugo/work/mcast/dbeacon/dump.xml";

my $dbeacon = "<a href=\"http://artemis.av.it.pt/~hsantos/software/dbeacon.html\">dbeacon</a>";

my $page = new CGI;
my $url = $page->script_name();

# if matrix.pl is being served as matrix/, history will be matrix/history/
# my $history = $url . "history/";
my $history = undef;

print $page->header;

my $attname = $page->param('att');
if (not $attname) {
	$attname = "ttl";
}

my $atthideinfo = $default_hideinfo;
if (defined($page->param('hideinfo'))) {
	$atthideinfo = $page->param('hideinfo');
}

my $attwhat = $default_what;
if (defined($page->param('what'))) {
	$attwhat = $page->param('what');
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

sub beacon_name {
	my ($d) = @_;
	my $name = $g->get_vertex_attribute($a, "name");

	return $name or "($d)";
}

start_document();

build_header();

my $what_td = "colspan=\"2\"";

if ($attwhat eq "asm") {
	$what_td = "";
}

print "<table border=\"0\" cellspacing=\"0\" cellpadding=\"0\" class=\"adjr\" id=\"adj\">\n";

my $c;
my $i = 1;
my @problematic = ();
my @warmingup = ();
my @localnoreceive = ();

my @V = $g->vertices();

print "<tr><td>&nbsp;</td>";
foreach $c (@V) {
	my $age = $g->get_vertex_attribute($c, "age");

	if (($age ne "") and ($age < 30)) {
		push (@warmingup, $c);
	} elsif (not $g->get_vertex_attribute($c, "goodedge")) {
		push (@problematic, $c);
	} else {
		print "<td $what_td><b>S$i</b></td>";
		$g->set_vertex_attribute($c, "id", $i);
		$i++;

		if (scalar($g->in_edges($c)) == 0) {
			push (@localnoreceive, $c);
		}
	}
}
print "</tr>\n";

# this should be in a package
sub make_history_url {
	my ($dst, $src, $type) = @_;

	my $dstbeacon = $dst->[0];
	my $srcbeacon = $src->[0];

	$dstbeacon =~ s/\/\d+$//;
        $srcbeacon =~ s/\/\d+$//;

	return "$history?src=" . $dst->[1] . ".$dstbeacon.$type&dst=" . $src->[1] . ".$srcbeacon";
}

sub build_name {
	my ($a) = @_;

	return [$a, $g->get_vertex_attribute($a, "name")];
}

sub make_history_link {
	my ($dst, $src, $type, $txt, $class) = @_;

	if ($history) {
		print "<a class=\"$class\" href=\"" . make_history_url(build_name($dst), build_name($src), $type) . "\">$txt</a>";
	} else {
		print $txt;
	}
}

sub make_matrix_cell {
	my ($dst, $src, $type, $txt, $class) = @_;

	if ($txt eq "") {
		print "<td class=\"noinfo_$type\">-</td>";
	} else {
		print "<td class=\"adjacent_$type\">";
		make_history_link($dst, $src, $type, $txt, $class);
		print '</td>';
	}
}

foreach $a (@V) {
	my $id = $g->get_vertex_attribute($a, "id");
	if ($id >= 1 and scalar($g->in_edges($a)) > 0) {
		print "<tr>";
		print "<td align=\"right\" class=\"beacname\">" . beacon_name($a) . " <b>R$id</b></td>";
		foreach $b (@V) {
			if ($g->get_vertex_attribute($b, "id") >= 1) {
				if ($b ne $a and $g->has_edge($b, $a)) {
					my $txt = $g->get_edge_attribute($b, $a, $attname);

					if ($attwhat eq "asm") {
						if ($txt eq "") {
							print "<td class=\"noinfo\">N/A</td>";
						} else {
							print "<td class=\"fulladjacent\">";
							make_history_link($b, $a, "asm", $txt, "historyurl");
							print "</td>";
						}
					} else {
						my $txtssm = $g->get_edge_attribute($b, $a, "ssm_" . $attname);

						if (($txt eq "") and ($txtssm eq "")) {
							print "<td colspan=\"2\" class=\"noinfo\">N/A</td>";
						} else {
							make_matrix_cell($b, $a, "asm", $txt, "historyurl");
							make_matrix_cell($b, $a, "ssm", $txtssm, "historyurl");
						}
					}
				} else {
					if ($a eq $b) {
						print "<td $what_td class=\"corner\">&nbsp;</td>";
					} else {
						print "<td $what_td class=\"blackhole\">XX</td>";
					}
				}
			}
		}
		print "</tr>\n";
	}
}
print "</table>\n";

if (scalar(@localnoreceive) > 0) {
	print "<h4 style=\"margin-bottom: 0\">The following beacons are not being received locally</h4>\n";
	print "<ul>\n";
	foreach $a (@localnoreceive) {
		my $id = $g->get_vertex_attribute($a, "id");
		my $contact = $g->get_vertex_attribute($a, "contact");
		print "<li><b>R$id</b> " . beacon_name($a);
		if ($contact) {
			print " ($contact)";
		}
		print "</li>\n";
	}
	print "</ul>\n";
}

if (not $atthideinfo) {
	print "<br />\n";

	print "<table border=\"0\" cellspacing=\"0\" cellpadding=\"0\" class=\"adjr\" id=\"adjname\">\n";

	print "<tr><td></td><td><b>Age</b></td><td><b>Source Address</b></td><td><b>Admin Contact</b></td><td><b>L/M</b></td></tr>\n";
	foreach $a (@V) {
		my $id = $g->get_vertex_attribute($a, "id");
		if ($id >= 1) {
			print "<tr>";
			print "<td align=\"right\" class=\"beacname\">";
			if ($g->has_vertex_attribute($a, "url_generic")) {
				print "<a class=\"beacon_url\" href=\"" . $g->get_vertex_attribute($a, "url_generic") . "\">";
			}
			print $g->get_vertex_attribute($a, "name");
			if ($g->has_vertex_attribute($a, "url_generic")) {
				print "</a>";
			}
			print " <b>R$id</b></td>";
			print "<td class=\"age\">" . format_date($g->get_vertex_attribute($a, "age")) . "</td>";
                        # Removing port number from id and link toward RIPE whois db
		        my $ip = $a;
		        $ip =~ s/\/\d+$//;
		        print "<td class=\"addr\"><a href=\"http://www.ripe.net/whois?form_type=simple&full_query_string=&searchtext=$ip&do_search=Search\"> $ip</a></td>";
			print "<td class=\"admincontact\">" . $g->get_vertex_attribute($a, "contact") . "</td>";

			my $urls;
			if ($g->has_vertex_attribute($a, "url_lg")) {
				$urls .= " <a href=\"" . $g->get_vertex_attribute($a, "url_lg") . "\">L</a>";
			}
			if ($g->has_vertex_attribute($a, "url_matrix")) {
				$urls .= " <a href=\"" . $g->get_vertex_attribute($a, "url_matrix") . "\">M</a>";
			}

			print "<td class=\"urls\">" . ($urls or "-") . "</td>";
			print "</tr>\n";
		}
	}
	print "</table>\n<br />\n";
}

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
		my @neighs = $g->neighbours($prob);

		print "<li>$prob";
		if ($name) {
			print " ($name, " . $g->get_vertex_attribute($prob, "contact") . ")";
		}

		my $ned = scalar(@neighs);
		my $k = $ned;
		if ($k > 3) {
			$k = 3;
		}

		print "<ul>Received from:<ul>\n";

		for (my $l = 0; $l < $k; $l++) {
			$name = $g->get_vertex_attribute($neighs[$l], "name");
			print "<li><span class=\"beacon\">" . $neighs[$l];
			if ($name) {
				print " ($name)";
			}
			print "</span></li>\n";
		}

		if ($k < $ned) {
			print "<li>and others</li>\n";
		}

		print "</ul></ul></li>\n";
	}
	print "</ul>\n";
}

print "<p>If you wish to add a beacon to your site, you may use $dbeacon with the following parameters:</p>\n";
print "<p><code>./dbeacon -n NAME -b $sessiongroup";
if ($ssm_sessiongroup) {
	print " -S $ssm_sessiongroup";
}
print " -a CONTACT</code></p>\n";

end_document();

sub format_date {
	my $tm = shift;

	if (not $tm) {
		return "-";
	}

	my $res;
	my $dosecs = 1;

	if ($tm > 86400) {
		my $days = $tm / 86400;
		$res .= " $days";
		$res .= "d";
		$tm = $tm % 86400;
		$dosecs = 0;
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

	if ($dosecs and $tm > 0) {
		$res .= " $tm";
		$res .= "s";
	}

	return $res;
}

sub start_handler {
	my ($p, $tag, %atts) = @_;
	my $name;
	my $value;

	if ($tag eq "group") {
		$sessiongroup = $atts{"addr"};
		$ssm_sessiongroup = $atts{"ssmgroup"};
	} elsif ($tag eq "beacon") {
		$current_beacon = $atts{"addr"};
		$current_source = "";

		if ($atts{"addr"} ne "") {
			if (($atts{"name"} ne "") and ($atts{"age"} > 0)) {
				$g->add_vertex($current_beacon);
				$g->set_vertex_attribute($current_beacon, "name", $atts{"name"});
				$g->set_vertex_attribute($current_beacon, "contact", $atts{"contact"});
				$g->set_vertex_attribute($current_beacon, "age", $atts{"age"});
			}
		}
	} elsif ($tag eq "asm") {
		if ($current_source ne "") {
			parse_stats($current_source, "", %atts);
		}
	} elsif ($tag eq "ssm") {
		if ($current_source ne "") {
			parse_stats($current_source, "ssm_", %atts);
		}
	} elsif ($tag eq "source") {
		$current_source = $atts{"addr"};

		if (($atts{"name"} ne "") and ($atts{"addr"} ne "")) {
			if (not $g->has_vertex($current_source)) {
				$g->add_vertex($current_source);

				$g->set_vertex_attribute($current_source, "name", $atts{"name"});
				$g->set_vertex_attribute($current_source, "contact", $atts{"contact"});
			}

			$g->add_edge($current_source, $current_beacon);
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

sub start_document {
	print "<?xml version=\"1.0\"?>\n";
	print "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n";
	print "<html xmlns=\"http://www.w3.org/1999/xhtml\" lang=\"en\" xml:lang=\"en\">\n";

	print "<head>
	\t<title>IPv6 Multicast Beacon</title>
\t<meta http-equiv=\"refresh\" content=\"60\" />
\t<style type=\"text/css\">
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
table#adj td.fulladjacent, table#adj td.adjacent_asm, table#adj td.adjacent_ssm {
	background-color: #96ef96;
	width: 20px;
}

table#adj td.blackhole {
	background-color: #000000;
}
table#adj td.noinfo {
	background-color: #ff0000;
}
table#adj td.noinfo_asm, table#adj td.noinfo_ssm {
	background-color: #b6ffb6;
	width: 20px;
}
table#adj td.corner {
	background-color: #dddddd;
}

table#adj td.adjacent_asm {
	border-right: 0.075em solid white;
}

table#adj td.blackhole, table#adj td.noinfo, table#adj td.fulladjacent, table#adj td.adjacent_ssm, table#adj td.corner, table#adj td.noinfo_ssm {
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

.addr a, .addr a:visited {
	text-decoration: none;
	color: black;
}

.beacon {
	font-style: italic;
}

ul#view {
	margin: 0;
	padding: 0;
}

ul#view li {
	display: inline;
	padding: 0;
	padding-left: 5px;
	margin: 0;
}

#view a.viewitem {
	color: blue;
	text-decoration: none;
	border-bottom: 1px solid blue;
}

#view a.viewitem:visited {
	color: blue;
}

#view #currentview {
	border-bottom: 1px dotted black;
}

a.historyurl, a.historyurl:visited {
	color: black;
	text-decoration: none;
}

\t</style>
</head>\n";

	print "<body>\n";

	print "<h1 style=\"margin: 0\">IPv6 Multicast Beacon</h1>\n";

	print "<small>Current server time is " . localtime() . "</small><br />\n";
	# print "<small>Last stats retrieved at " . (stat($dump_file))[9] . "</small><br />\n";
}

sub build_header {
	print "<br /><b>Current stats for</b> <code>$sessiongroup</code>";
	if ($ssm_sessiongroup) {
		print " (SSM: <code>$ssm_sessiongroup</code>)";
	}
	print "<br /><br />\n";

	my $hideatt;

	if ($atthideinfo) {
		$hideatt = "hideinfo=1&";
	}

	my $whatatt = "what=$attwhat&";

	my @view = ("ttl", "loss", "delay", "jitter");
	my @view_name = ("TTL", "Loss", "Delay", "Jitter");
	my @view_type = ("hop count", "percentage", "ms", "ms");

	my $view_len = scalar(@view);
	my $i;

	print "<span style=\"float: left\"><b>View</b>&nbsp;<small>(";

	if (not $atthideinfo) {
		print "<a href=\"$url?hideinfo=1&$whatatt&att=$attname\">Hide Source Info</a>";
	} else {
		print "<a href=\"$url?hideinfo=0&$whatatt&att=$attname\">Show Source Info</a>";
	}

	if ($attwhat eq "asm") {
		print ", <a href=\"$url?$hideatt&what=both&att=$attname\">ASM and SSM</a>";
	} else {
		print ", <a href=\"$url?$hideatt&what=asm&att=$attname\">ASM only</a>";
	}

	print ")</small>:</span>";

	print "<ul id=\"view\" style=\"float: left\">\n";
	for ($i = 0; $i < $view_len; $i++) {
		my $att = $view[$i];
		my $attn = $view_name[$i];
		print "<li>";
		if ($attname eq $att) {
			print "<span class=\"viewitem\" id=\"currentview\">$attn</span>";
		} else {
			print "<a class=\"viewitem\" href=\"$url?$hideatt$whatatt" . "att=$att\">$attn</a>";
		}
		print " <small>(" . $view_type[$i] . ")</small></li>\n";
	}
	print "</ul>\n";

	print "<br /><br />\n";
}

sub end_document {
	print "<hr />\n";
	print "<small>matrix.pl - a tool for dynamic viewing of $dbeacon information. by Hugo Santos and Hoerdt Mickaël</small>\n";

	print "</body>\n";
	print "</html>\n";
}
