#!/usr/bin/perl -w

# matrix.pl - displays dbeacon dump information in a matrix,
#		or stores it in RRD files and displays it
#
# To use it you can add this line in your apache config file:
# ScriptAlias /matrix/ /path/to/dbeacon/contrib/matrix.pl
#
# by Hugo Santos, Sebastien Chaumontet and Hoerdt Mickaël

use CGI;
use Graph::Directed;
use XML::Parser;
use RRDs;
use POSIX qw(strftime);
use strict;

# configuration variables, may be changed in matrix.conf
our $dumpfile = "/home/seb/dbeacon/dump.xml";
our $historydir = 'data';
our $verbose = 1;
our $title = "IPv6 Multicast Beacon";
our $page_title = $title;
our $default_hideinfo = 0;	# one of '0', '1'
our $default_what = "ssmorasm";	# one of 'ssmorasm', 'both', 'asm'
our $history_enabled = 1;
our $css_file;
our $dump_update_delay = 5;	# time between each normal dumps (used to detect outdated dump files)

do("matrix.conf");

my $dbeacon = "<a href=\"http://artemis.av.it.pt/~hsantos/software/dbeacon.html\">dbeacon</a>";

my $g;
my $sessiongroup;
my $ssm_sessiongroup;

if (scalar(@ARGV) > 0) {
	exit(store_data($ARGV[0]));
}

my $page = new CGI;
my $url = $page->script_name();

my $dst = $page->param('dst');
my $src = $page->param('src');
my $type = $page->param('type');
my $age = $page->param('age');
my $at = $page->param('at');

my %ages = (
	"-1h" => "Hour",
	"-6h" => "6 Hours",
	"-12h" => "12 Hours",
	"-1d" => "Day",
	"-1w" => "Week",
	"-1m" => "Month",
	"-1y" => "Year");

my @propersortedages = ("-1m", "-1w", "-1d", "-12h", "-6h", "-1h");

if (not defined($age)) {
	$age = '-1d';
}

if (defined($history_enabled) and $history_enabled and defined($page->param('img'))) {
	$|=1;
	graphgen();

} elsif (defined($history_enabled) and $history_enabled and defined($page->param('history'))) {
	list_graph();

} else {
	my ($start,$step);

	if (defined ($page->param('at')) and $page->param('at')=~/^\d+$/) {
		# Build matrix from old data
		($start,$step) = build_vertex_from_rrd();
	} else {
		# Buils matrix from live data
		parse_dump_file($dumpfile);
	}

	render_matrix($start,$step);
}

sub build_vertex_from_rrd {

	my ($start,$step,$names,$data);

	$g = new Graph::Directed;

	foreach my $dstbeacon (get_beacons($historydir)) {
		my ($dstname,$dstaddr) = get_name_from_host($dstbeacon);
		$g->add_vertex($dstaddr);
		$g->set_vertex_attribute($dstaddr, "name", $dstname);
		foreach my $srcbeacon (get_beacons($historydir.'/'.$dstbeacon)) {
			my ($srcname,$srcaddr,$asmorssm) = get_name_from_host($srcbeacon);

			if (not $g->has_vertex($srcaddr)) {
				$g->add_vertex($srcaddr);
				$g->set_vertex_attribute($srcaddr, "name", $srcname);
			}

			$g->add_edge($srcaddr, $dstaddr);
			$g->set_vertex_attribute($srcaddr, "goodedge", 1);

			($start,$step,$names,$data) = RRDs::fetch(build_rrd_file_path($historydir,  $dstbeacon, $srcbeacon, $asmorssm), 'AVERAGE',
				 '-s',$page->param('at'),'-e',$page->param('at'));
			
			if (RRDs::error) {
				next;
			}
			
			my $prefix ="";
			if ($asmorssm eq "ssm") {
				$prefix="ssm_";
			}

			for (my $i = 0; $i < $#$names+1; $i++) {
				if (defined($$data[0][$i])) {
					if ($$names[$i] =~ /^(delay|jitter)$/) {
						$$data[0][$i] *= 1000;
					}
					$g->set_edge_attribute($srcaddr, $dstaddr, $prefix.$$names[$i], $$data[0][$i]);
				}
			}
		}
	}
	return ($start,$step);
}

sub full_url0 {
	return "$url?dst=$dst&src=$src";
}

sub full_url {
	if (not defined($type))
	{
		$type = "ttl";
	}
	return "$url?dst=$dst&src=$src&type=$type";
}

sub parse_dump_file {
	my ($dump) = @_;

	$g = new Graph::Directed;

	my $parser = new XML::Parser(Style => 'Tree');
	$parser->setHandlers(Start => \&start_handler);
	my $tree = $parser->parsefile($dump);
}

sub check_outdated_dump {
	my $last_update_time = (stat($dumpfile))[9];

	if ($last_update_time+($dump_update_delay*2) < time()) {
		return $last_update_time;
	} else {
		return 0;
	}
}

sub beacon_name {
	my ($d) = @_;
	my $name = $g->get_vertex_attribute($a, "name");

	return $name or "($d)";
}

sub make_history_url {
	my ($dst, $src, $type) = @_;

	my $dstbeacon = $dst->[0];
	my $srcbeacon = $src->[0];

	$dstbeacon =~ s/\/\d+$//;
        $srcbeacon =~ s/\/\d+$//;

	return "$url?history=1&src=" . $dst->[1] . "-$dstbeacon.$type&dst=" . $src->[1] . "-$srcbeacon";
}

sub build_name {
	my ($a) = @_;

	return [$a, $g->get_vertex_attribute($a, "name")];
}

sub make_history_link {
	my ($dst, $src, $type, $txt, $class) = @_;

	if ($history_enabled) {
		print "<a class=\"$class\" href=\"" . make_history_url(build_name($dst), build_name($src), $type) . "\">$txt</a>";
	} else {
		print $txt;
	}
}

sub make_matrix_cell {
	my ($dst, $src, $type, $txt, $class) = @_;

	if (not defined($txt)) {
		print "<td class=\"noinfo_$type\">-</td>";
	} else {
		print "<td class=\"adjacent_$type\">";
		make_history_link($dst, $src, $type, $txt, $class);
		print '</td>';
	}
}

sub format_date {
	my $tm = shift;

	if (not $tm) {
		return "-";
	}

	my $res;
	my $dosecs = 1;

	if ($tm > 86400) {
		$res .= sprintf(" %id", $tm / 86400);
		$tm = $tm % 86400;
		$dosecs = 0;
	}

	if ($tm > 3600) {
		$res .= sprintf(" %ih", $tm / 3600);
		$tm = $tm % 3600;
	}

	if ($tm > 60) {
		$res .= sprintf(" %im", $tm / 60);
		$tm = $tm % 60;
	}

	if ($dosecs and $tm > 0) {
		$res .= " $tm";
		$res .= "s";
	}

	return $res;
}

my $current_beacon;
my $current_source;

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
			if (defined($atts{"name"}) and defined($atts{"age"}) and ($atts{"age"} > 0)) {
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

		if (defined($atts{"name"}) and defined($atts{"addr"})) {
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
		$g->set_vertex_attribute($addr, "goodedge", 1);
	}

	foreach my $att ('loss', 'delay', 'jitter') {
		if (defined($atts{$att})) {
			$g->set_edge_attribute($addr, $current_beacon, "$prefix$att", $atts{$att});
		}
	}
}

sub start_document {
	my ($additionalinfo) = @_;

	start_base_document();

	print "<h1 style=\"margin: 0\">$title</h1>\n";

	print "<small>Current server time is " . localtime() ."$additionalinfo</small><br />\n";
}

sub build_header {
	my ($attname, $atthideinfo, $attwhat, $start, $step) = @_;

	if (defined($step)) { # From history
		print "<br /><b>Snapshot stats at ".localtime($start)."</b> ($step seconds average) ";
		print "<br /><br />\n";

		print '<form name="timenavigator">';
		print 'Time navigation: ';
		print '<script language="javascript"> 
			function move(way) {
				selectedvalue = document.timenavigator.offset.options[document.timenavigator.offset.selectedIndex].value;
				newdate = '.$at.' + selectedvalue * way;
				url = "'."$url?what=$attwhat&att=$attname&at=".'"+newdate;
				location.href=url;
			}</script>';

		print '<a href="javascript:move(-1)"><small>Move backward</small> &lt;</a>'; 

		#print '<select name="offset" onChange="location = this.options[this.selectedIndex].value;">'."\n";
		print '<select name="offset">'."\n";

		print '<option value="60"> 60 s';
		print '<option value="600"> 10 mn';
		print '<option value="3600"> 60 mn';
		print '<option value="36000"> 10 h';
		print '<option value="86400"> 24 h';
		print '<option value="604800"> 7 days';
		print '<option value="2592000"> 30 days';
		print '<option value="7884000"> 3 months';

		print "</select>";

		print '<a href="javascript:move(1)">&gt; <small>Move forward</small></a>';
		print '<br />';
		print '</form>';

	} else {
	print "<br /><b>Current stats for</b> <code>$sessiongroup</code>";
	if ($ssm_sessiongroup) {
		print " (SSM: <code>$ssm_sessiongroup</code>)";
	}

	print "<br />";

	my $last_update_time = check_outdated_dump();
	if ($last_update_time) {
		print '<font color="#ff0000">Warning: outdated informations, last dump was updated ' . localtime($last_update_time) . "</font><br />\n";
	}

	print "<br />";
}
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
	if (not defined($attname)){
		$attname = "";
	}
	if (not defined($hideatt)){
		$hideatt = "";
	}
	if (not defined($at)){
		$at = "";
	}

	if (not $atthideinfo) {
		print "<a href=\"$url?hideinfo=1&$whatatt&att=$attname&at=$at\">Hide Source Info</a>";
	} else {
		print "<a href=\"$url?hideinfo=0&$whatatt&att=$attname&at=$at\">Show Source Info</a>";
	}

	if ($attwhat eq "asm") {
		print ", <a href=\"$url?$hideatt&what=both&att=$attname&at=$at\">ASM and SSM</a>";
		print ", <a href=\"$url?$hideatt&what=ssmorasm&att=$attname&at=$at\">SSM or ASM</a>";
	} elsif ($attwhat eq "ssmorasm") {
		print ", <a href=\"$url?$hideatt&what=both&att=$attname&at=$at\">ASM and SSM</a>";
		print ", <a href=\"$url?$hideatt&what=asm&att=$attname&at=$at\">ASM only</a>";
	} else {
		print ", <a href=\"$url?$hideatt&what=ssmorasm&att=$attname&at=$at\">SSM or ASM</a>";
		print ", <a href=\"$url?$hideatt&what=asm&att=$attname&at=$at\">ASM only</a>";
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
			print "<a class=\"viewitem\" href=\"$url?$hideatt$whatatt" . "att=$att&at=$at\">$attn</a>";
		}
		print " <small>(" . $view_type[$i] . ")</small></li>\n";
	}
	print "</ul>\n";

	print "<br /><br />\n";
}

sub end_document {
	print "<hr />\n";
	print "<small>matrix.pl - a tool for dynamic viewing of $dbeacon information and history. by Hugo Santos, Sebastien Chaumontet and Hoerdt Mickaël</small>\n";

	print "</body>\n";
	print "</html>\n";
}

sub make_ripe_search_url {
	my ($ip) = @_;

	return "http://www.ripe.net/whois?form_type=simple&full_query_string=&searchtext=$ip&do_search=Search";
}

sub render_matrix {

	my ($start,$step) = @_;

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

	my $what_td = "colspan=\"2\"";

	if ($attwhat eq "asm" or $attwhat eq "ssmorasm") {
		$what_td = "";
	}

	my $attat = $page->param('at');
	my $addinfo;
	if ($attat > 0) {
		$addinfo = " (<a href=\"$url?what=$attwhat&att=$attname\">Live stats</a>)";
	} else {
		$addinfo = " (<a href=\"$url?what=$attwhat&att=$attname&at=".time()."\">Past stats</a>)"
	}

	start_document($addinfo);

	build_header($attname, $atthideinfo, $attwhat, $start, $step);

	my $c;
	my $i = 1;
	my @problematic = ();
	my @warmingup = ();
	my @localnoreceive = ();

	my @V = $g->vertices();

	print "<table border=\"0\" cellspacing=\"0\" cellpadding=\"0\" class=\"adjr\" id=\"adj\">\n";
	print "<tr><td>&nbsp;</td>";
	foreach $c (@V) {
		my $age = $g->get_vertex_attribute($c, "age");

		if ((defined($age)) and ($age < 30)) {
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

	foreach $a (@V) {
		my $id = $g->get_vertex_attribute($a, "id");
		if ($id >= 1 and scalar($g->in_edges($a)) > 0) {
			print "<tr>";
			print "<td align=\"right\" class=\"beacname\">" . beacon_name($a) . " <b>R$id</b></td>";
			foreach $b (@V) {
				if ($g->get_vertex_attribute($b, "id") >= 1) {
					if ($b ne $a and $g->has_edge($b, $a)) {
						my $txt = $g->get_edge_attribute($b, $a, $attname);

						if (($attname eq 'delay' or $attname eq 'jitter') and defined($txt)) {
							$txt = sprintf("%.1f", $txt);
						}

						if ($attwhat eq "asm" or $attwhat eq "ssmorasm") {
							my $whattype = "asm";
							my $cssclass = "fulladjacent";
							if ($attwhat eq "ssmorasm") {
								my $txtssm = $g->get_edge_attribute($b, $a, "ssm_" . $attname);
								if (defined($txtssm)) {
									$txt = $txtssm;
									$whattype = "ssm";
								} elsif (defined($txt)) {
									$cssclass = "nossm_fulladjacent";
									$txt = "<i>$txt</i>";
								}
							}

							if (not defined($txt)) {
								print "<td $what_td class=\"blackhole\">XX</td>";
							} else {
								print "<td class=\"$cssclass\">";
								make_history_link($b, $a, $whattype, $txt, "historyurl");
								print "</td>";
							}
						} else {
							my $txtssm = $g->get_edge_attribute($b, $a, "ssm_" . $attname);

							if (not defined($txt) and not defined($txtssm)) {
								print "<td $what_td class=\"blackhole\">XX</td>";
							} else {
								if (($attname eq 'delay' or $attname eq 'jitter') and defined($txtssm)) {
									$txtssm = sprintf("%.1f", $txtssm);
								}
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
				print " <b>R$id</b>";
				# print "<img src=\"http://www.sixxs.net/gfx/countries/jp.gif\" style=\"vertical-align: middle; margin-left: 0.4em; border: 1px solid black\" />";
				print "</td>";
				print "<td class=\"age\">" . format_date($g->get_vertex_attribute($a, "age")) . "</td>";
				# Removing port number from id and link toward RIPE whois db
			        my $ip = $a;
			        $ip =~ s/\/\d+$//;
			        print "<td class=\"addr\"><a href=\"" . make_ripe_search_url($ip) . "\">$ip</a></td>";
				if (defined($g->get_vertex_attribute($a, "contact"))) {
					print "<td class=\"admincontact\">" . $g->get_vertex_attribute($a, "contact") . "</td>";
				} else {
					print "<td class=\"admincontact\"></td>";
				}

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

	print "<p>If you wish to add a beacon to your site, you may use $dbeacon";
	if (defined($step)) {
		print ".</p>\n";
	} else {
		print " with the following parameters:</p>\n";
		print "<p><code>./dbeacon -n NAME -b $sessiongroup";
		if ($ssm_sessiongroup) {
			print " -S $ssm_sessiongroup";
		}
		print " -a CONTACT</code></p>\n";
	}


	end_document();
}

sub store_data {

	if (check_outdated_dump()) {
		die "Outdated dumpfile\n";
	}
	parse_dump_file(@_);

	my @verts = $g->vertices();

	foreach my $a (@verts) {
		my $a_name = $g->get_vertex_attribute($a, "name");
		if (defined($a_name)) {
			foreach my $b (@verts) {
				if ($a ne $b and $g->has_edge($b, $a)) {
					my $b_name = $g->get_vertex_attribute($b, "name");
					if (defined($b_name)) {
						store_data_one($a, $a_name, $b, $b_name, "asm", "");
						store_data_one($a, $a_name, $b, $b_name, "ssm", "ssm_");
					}
				}
			}
		}
	}

	return 0;
}

sub store_data_one {
	my ($dst, $dstname, $src, $srcname, $tag, $prefix) = @_;

	my $dst_h = build_host($dstname, $dst);
	my $src_h = build_host($srcname, $src);

	my %values;

	my $good = 0;

	foreach my $type ('ttl', 'loss', 'delay', 'jitter') {
		$values{$type} = $g->get_edge_attribute($src, $dst, "$prefix$type");
		if (defined($values{$type})) {
			$good++;
		}
	}

	if ($good > 0) {
		storedata($dst_h, $src_h, $tag, %values);
	}
}

sub build_host {
	my ($name, $addr) = @_;

	# Removing port number as it change between two beacon restarts
        $addr =~ s/\/\d+$//;

	# Removing bad chars in name
        $name =~ s/[^A-z0-9\:\.\-_\s]//g;

	return "$name-$addr";
}

sub build_rrd_file_path {
	my ($historydir, $dstbeacon, $srcbeacon, $asmorssm) = @_;

	$srcbeacon =~ s/\.(ssm|asm)$//;

	return "$historydir/$dstbeacon/$srcbeacon.$asmorssm.rrd";
}
sub make_rrd_file_path {
	my ($historydir, $dstbeacon, $srcbeacon, $asmorssm) = @_;

	if (! -d "$historydir/$dstbeacon") {
		if (! -d $historydir) {
			if (!mkdir $historydir) {
				return 0;
			}
		}
		return mkdir "$historydir/$dstbeacon";
	}

	return 1;
}

sub check_rrd {
	my ($historydir, $dstbeacon, $srcbeacon, $asmorssm) = @_;

	my $rrdfile = build_rrd_file_path(@_);

	if (! -f $rrdfile) {
		if ($verbose) {
			print "New combination: RRD file $rrdfile needs to be created\n";
		}

		if (!make_rrd_file_path(@_)) {
			return 0;
		}

		if (!RRDs::create($rrdfile,
			'-s 60',			# steps in seconds
			'DS:ttl:GAUGE:90:0:255',	# 90 seconds befor reporting it as unknown
			'DS:loss:GAUGE:90:0:100',	# 0 to 100%
			'DS:delay:GAUGE:90:0:U',	# Unknown max for delay
			'DS:jitter:GAUGE:90:0:U',	# Unknown max for jitter
			'RRA:MIN:0.5:1:1440',		# Keeping 24 hours at high resolution
			'RRA:MIN:0.5:5:2016',		# Keeping 7 days at 5 min resolution
			'RRA:MIN:0.5:30:1440',		# Keeping 30 days at 30 min resolution
			'RRA:MIN:0.5:120:8784',		# Keeping one year at 2 hours resolution
			'RRA:AVERAGE:0.5:1:1440',
			'RRA:AVERAGE:0.5:5:2016',
			'RRA:AVERAGE:0.5:30:1440',
			'RRA:AVERAGE:0.5:120:8784',
			'RRA:MAX:0.5:1:1440',
			'RRA:MAX:0.5:5:2016',
			'RRA:MAX:0.5:30:1440',
			'RRA:MAX:0.5:120:8784')) {
			return 0;
		}
	}

	return 1;
}

sub storedata {
	my ($dstbeacon, $srcbeacon, $asmorssm, %values) = @_;

	check_rrd($historydir, $dstbeacon, $srcbeacon, $asmorssm);

	# Update rrd with new values

	my $updatestring = 'N';
	foreach my $valuetype ('ttl', 'loss', 'delay', 'jitter') {
		if ($valuetype eq 'delay' or $valuetype eq 'jitter') {
			# Store it in s and not ms
			$values{$valuetype} = $values{$valuetype} / 1000.;
		}
		$updatestring .= ':' . $values{$valuetype};
	}

	if ($verbose > 1) {
		print "Updating $dstbeacon <- $srcbeacon with $updatestring\n";
	}

	if (!RRDs::update(build_rrd_file_path($historydir, $dstbeacon, $srcbeacon, $asmorssm), $updatestring)) {
		return 0;
	}

	return 1;
}

sub graphgen {
	my $title;
	my $ytitle;
	my $unit;

	if ($type eq 'ttl') { $title = 'TTL'; $ytitle = 'Hops'; $unit = '%3.0lf hops' }
	elsif ($type eq 'loss') { $title = 'Loss'; $ytitle = '% of packet loss'; $unit = '%2.1lf %%' }
	elsif ($type eq 'delay') { $title = 'Delay'; $ytitle = 'Seconds'; $unit = '%2.2lf %ss' }
	elsif ($type eq 'jitter') { $title = 'Jitter'; $ytitle = 'Seconds'; $unit = '%2.2lf %ss' }
	else { die "Unknown type\n"; }

	# Display only the name
	my ($msrc,undef,$asmorssm) = get_name_from_host($src);
	my ($mdst) = get_name_from_host($dst);

	my $rrdfile = build_rrd_file_path($historydir, $dst, $src, $asmorssm);

	# Escape ':' chars
	$rrdfile =~ s/:/\\:/g;

	$asmorssm =~ s/([a-z])/\u$1/g; # Convert to uppercase

	print $page->header(-type => 'image/png', -expires => '+3s');

	my $width = 450;
	my $height = 150;

	if (defined($page->param('thumb'))) {
		$width = 300;
		$height = 100;
		$title .= " ($ytitle)";
	} else {
		$title.= " from $msrc to $mdst ($asmorssm)";
	}

	my @args = ('-',
		'--imgformat', 'PNG',
		'--start', $age,
		"--width=$width",
		"--height=$height",
		"--title=$title",
		"DEF:Max=$rrdfile:$type:MAX",
		"DEF:Avg=$rrdfile:$type:AVERAGE",
		"DEF:Min=$rrdfile:$type:MIN",
		'CDEF:nodata=Max,UN,INF,UNKN,IF',
		'AREA:nodata#E0E0FD');

	if (not defined($page->param('thumb'))) {
		push (@args,  '--vertical-label',$ytitle);
		push (@args, 'COMMENT:'.strftime("%a %b %e %Y %H:%M (%Z)",localtime).' '.strftime("%H:%M (GMT)",gmtime).'\r');
		push (@args, 'AREA:Max#FF0000:Max');
		push (@args, 'GPRINT:Max:MAX:'.$unit);
		push (@args, 'AREA:Avg#CC0000:Avg');
		push (@args, 'GPRINT:Avg:AVERAGE:'.$unit);
		push (@args, 'AREA:Min#990000:Min');
		push (@args, 'GPRINT:Min:MIN:'.$unit);
	} else {
		push (@args, 'AREA:Avg#CC0000:Avg');
		push (@args, 'GPRINT:Avg:AVERAGE:'.$unit);
	}

	push (@args, 'GPRINT:Max:LAST:Last '.$unit.'\n');

	if (!RRDs::graph(@args)) {
		die(RRDs::error);
	}
}

sub get_beacons {
        my ($target, $isf, $start) = @_;

        opendir (DIR, $target) or die "Failed to open directory $target\n";
        my @res = ();

        foreach my $dircontent (readdir(DIR)) {
                if ($dircontent ne "." and $dircontent ne "..") {
			$dircontent =~ s/\.rrd$//;
			push (@res, $dircontent);
                }
        }

        close (DIR);

        return @res;
}

sub get_name_from_host {
	my ($host) = @_;

	if ($host =~ /^(.+)\-(.+)\.(ssm|asm)$/)
	{
		return ($1,$2,$3);
	}
	elsif ($host =~ /^(.+)\-(.+)$/)
	{
		return ($1,$2);
	}
	return 0;
}

sub do_list_beacs {
	my ($name, $dst, $src, @vals) = @_;

	print '<select name="'.$name.'" onChange="location = this.options[this.selectedIndex].value;">'."\n";

	my $def;
	if ($name eq 'srcc') {
		$def = $src;
	} else {
		$def = $dst;
	}

	foreach my $foo (@vals) {
		print '<option value="'.$url.'?history=1&dst=';
		if ($name eq 'srcc') {
			print $dst.'&src='.$foo;
		} else {
			print $foo;
		}
		print '"';

		if ($foo eq $def) {
			print " selected";
		}

		print ">" . (get_name_from_host($foo))[0] ;
		if ($name eq 'srcc') {
			print ' ('.(get_name_from_host($foo))[2].')';
		}
		print "</option>\n";
	}

	print "</select>\n";

}

sub graphthumb {
	my ($type) = shift;
	print '<a href="' . full_url0() . "&history=1&type=$type\">\n";
	print '<img style="margin-right: 0.5em; margin-bottom: 0.5em" border="0" src="'.full_url0()."&type=$type&img=true&thumb=true&age=$age\" /></a><br />\n";
}

sub list_graph {
	start_document(" (<a href=\"$url\">Live stats</a>)");

	print "<br />\n";

        if (defined($dst)) {
               print "To ";

               do_list_beacs("dstc", $dst, undef, get_beacons($historydir));

               if (defined($src)) {
                       print "From ";
                       do_list_beacs("srcc", $dst, $src, get_beacons("$historydir/$dst"));

                       if (defined($type)) {
                               print "Type ";

                               my @types = (["-- All --", "", ""], ["TTL", "ttl", ""], ["Loss", "loss", ""], ["Delay", "delay", ""], ["Jitter", "jitter", ""]);

				print '<select name="type" onChange="location = this.options[this.selectedIndex].value;">'."\n";

				foreach my $foo (@types) {
					print '<option value="'.full_url0() . '&history=1&type=' . $$foo[1].'" ';
					if ($type eq $$foo[1]) {
						print 'selected';
					}
					print '>'.$$foo[0]."\n";;
				}
				print "</select>\n";
			}
		}

		print "<br />";
	}

	if (not defined($dst)) {

		# List beacon receiving infos

		print 'Select a receiver:';

		my @beacs = get_beacons($historydir);

		print "<ul>\n";

		foreach my $beac (@beacs) {
			print '<li><a href="'.$url.'?history=1&dst=' . $beac . '">' . (get_name_from_host($beac))[0] . "</a></li>\n";
		}

		print "</ul>\n";

	} elsif (not defined($src)) {
		print '<br />Select a source:';

		# List visible src for this beacon

		my @beacs = get_beacons("$historydir/$dst");

		my %pairs;

		foreach my $beac (@beacs) {
			my ($name,$addr,$asmorssm) = get_name_from_host($beac);
			if ($asmorssm eq 'asm') {
				$pairs{build_host($name,$addr)}[0]=$beac;
			} elsif ($asmorssm eq 'ssm') {
				$pairs{build_host($name,$addr)}[1]=$beac;
			}
		}

		print "<ul>\n";
		foreach my $key (keys %pairs) {
			print "<li>";

			if (defined($pairs{$key}[0])) {
				print '<a href="?history=1&dst='.$dst.'&src=' . $pairs{$key}[0] . '">';
			}

			print ((get_name_from_host($key))[0]);

			if (defined($pairs{$key}[0])) {
				print '</a>';
			}

			if (defined($pairs{$key}[1])) {
				print ' / <a href="?history=1&dst='.$dst.'&src=' . $pairs{$key}[1] . "\">SSM</a>";
			}

			print "</li>\n";
		}
		print "</ul>\n";
	}  elsif (not defined($type)) {
		print "<div style=\"margin-left: 2em\">\n";
		print "<h2 style=\"margin-bottom: 0\">History for the last " . $ages{$age} . "</h2>\n";
		print "<small>Click on a graphic for more detail</small><br />\n";
		print "<table style=\"margin-top: 0.6em\">";

		my $count = 0;

		foreach my $type ("ttl", "loss", "delay", "jitter") {
			if (($count % 2) == 0) {
				print "<tr>";
			}
			print "<td>";
			graphthumb($type);
			print "</td>\n";
			if (($count % 2) == 1) {
				print "</tr>\n";
			}
			$count++;
		}

		print "</table>\n";

		print "<p>Last: ";

		foreach my $agen (@propersortedages) {
			print " <a href=\"" . full_url0() . "&history=1&age=" . $agen . "\">" . $ages{$agen} . "</a>";
		}

		print "</p>\n";
		print "</div>\n";
	} else {
		print "<br />";
		print "<div style=\"margin-left: 2em\">\n";
		# Dst, src and type selected => Displaying all time range graphs
		foreach my $age ('-1d','-1w','-1m','-1y') {
			print "<img style=\"margin-bottom: 0.5em\" src=\"" . full_url() . "&age=$age&img=true\" /><br />";
		}
		print "</div>";
	}

	end_document();
}

sub start_base_document {
	print $page->header;

	print "<?xml version=\"1.0\"?>\n";
	print "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n";
	print "<html xmlns=\"http://www.w3.org/1999/xhtml\" lang=\"en\" xml:lang=\"en\">\n";

	print "<head>
	<title>$page_title</title>
	<meta http-equiv=\"refresh\" content=\"60\" />\n";

	if ($css_file) {
		print "\t<link rel=\"stylesheet\" text=\"text/css\" href=\"$css_file\" />\n";
	} else {
		print_default_style();
	}

	print "</head>\n<body>\n";
	print "<body>\n";
}

sub print_default_style() {
	print "\t<style type=\"text/css\">
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

table#adj td.nossm_fulladjacent {
	background-color: #c0ffc0;
	width: 20px;
}

table#adj td.blackhole {
	background-color: #000000;
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

table#adj td.blackhole, table#adj td.fulladjacent, table#adj td.nossm_fulladjacent, table#adj td.adjacent_ssm, table#adj td.corner, table#adj td.noinfo_ssm {
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

\t</style>";
}

