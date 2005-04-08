#!/usr/bin/perl -w

# matrix.pl - displays dbeacon dump information in a matrix,
#		or stores it in RRD files and displays it
#
# To use it you can add this line in your apache config file:
# ScriptAlias /matrix/ /path/to/dbeacon/contrib/matrix.pl
#
# by Hugo Santos, Sebastien Chaumontet and Hoerdt Mickaël
#
#   Perl code improvement suggestions by Marco d'Itri

use CGI;
use XML::Parser;
use POSIX qw(strftime);
use Time::HiRes qw(gettimeofday tv_interval);
use strict;

# configuration variables, may be changed in matrix.conf
our $dumpfile = '/home/seb/dbeacon/dump.xml';
our $historydir = 'data';
our $verbose = 1;
our $title = 'IPv6 Multicast Beacon';
our $page_title = $title;
our $default_hideinfo = 0;	# one of '0', '1'
our $default_what = 'ssmorasm';	# one of 'ssmorasm', 'both', 'asm'
our $history_enabled = 0;
our $css_file;
our $dump_update_delay = 5;	# time between each normal dumps (used to detect outdated dump files)
our $flag_url_format = 'http://www.sixxs.net/gfx/countries/%s.gif';
our $default_ssm_group = 'ff3e::beac/10000';
our $debug = 0;
our $matrix_link_title = 0;
our $default_full_matrix = 0;
our $faq_page = 'http://artemis.av.it.pt/~hsantos/dbeacon/FAQ.html';

my $ssm_ping_url = 'http://www.venaas.no/multicast/ssmping/';

if (-f '/etc/dbeacon/matrix.conf') {
	do '/etc/dbeacon/matrix.conf';
}

if (-f 'matrix.conf') {
	do 'matrix.conf';
}

if ($history_enabled) {
	use RRDs;
}

my $dbeacon = '<a href="http://artemis.av.it.pt/~hsantos/dbeacon/">dbeacon</a>';

use constant NEIGH => 0;
use constant IN_EDGE => 1;
use constant OUT_EDGE => 2;
use constant NAME => 3;
use constant CONTACT => 4;
use constant COUNTRY => 5;
use constant AGE => 6;
use constant URL => 7;
use constant LG => 8;
use constant MATRIX => 9;
use constant RX_LOCAL => 10;
use constant SSM_PING => 11;

my %adj;

my $sessiongroup;
my $ssm_sessiongroup;

my $load_start = [gettimeofday];
my $ended_parsing_dump;

exit(store_data($ARGV[0])) if scalar(@ARGV) > 0;

my $page = new CGI;
my $url = $page->script_name();

my $dst = $page->param('dst');
my $src = $page->param('src');
my $type = $page->param('type');
my $age = $page->param('age');
my $at = $page->param('at');

my %ages = (
	'-1h' => 'Hour',
	'-6h' => '6 Hours',
	'-12h' => '12 Hours',
	'-1d' => 'Day',
	'-1w' => 'Week',
	'-1m' => 'Month',
	'-1y' => 'Year');

my @propersortedages = ('-1m', '-1w', '-1d', '-12h', '-6h', '-1h');

$age ||= '-1d';

if (defined $history_enabled and $history_enabled and defined $page->param('img')) {
	$|=1;
	graphgen();

} elsif (defined $history_enabled and $history_enabled and defined $page->param('history')) {
	list_graph();

} else {
	my ($start, $step);

	if (defined $page->param('at') and $page->param('at') =~ /^\d+$/) {
		# Build matrix from old data
		($start, $step) = build_vertex_from_rrd();
	} else {
		# Buils matrix from live data
		parse_dump_file($dumpfile);
	}

	render_matrix($start, $step);
}

sub build_vertex_from_rrd {
	my ($start, $step, $names, $data);

	foreach my $dstbeacon (get_beacons($historydir)) {
		my ($dstname,$dstaddr) = get_name_from_host($dstbeacon);

		if (not defined $adj{$dstaddr}) {
			$adj{$dstaddr}[IN_EDGE] = 0;
			$adj{$dstaddr}[OUT_EDGE] = 0;
		}

		$adj{$dstaddr}[NAME] = $dstname;

		foreach my $srcbeacon (get_beacons($historydir . '/' . $dstbeacon)) {
			my ($srcname, $srcaddr, $asmorssm) = get_name_from_host($srcbeacon);

			($start, $step, $names, $data) = RRDs::fetch(build_rrd_file_path($historydir,  $dstbeacon, $srcbeacon, $asmorssm), 'AVERAGE',
				 '-s', $page->param('at'), '-e', $page->param('at'));

			next if RRDs::error;

			if (not defined($adj{$srcaddr})) {
				$adj{$srcaddr}[IN_EDGE] = 0;
				$adj{$srcaddr}[OUT_EDGE] = 0;
			}

			$adj{$srcaddr}[NAME] = $srcname if defined $srcname;

			my $index = $asmorssm eq 'ssm' ? 2 : 1;

			for (my $i = 0; $i < $#$names+1; $i++) {
				if (defined $$data[0][$i]) {
					if ($$names[$i] =~ /^(delay|jitter)$/) {
						$$data[0][$i] *= 1000;
					}

					if (not defined $adj{$dstaddr}[NEIGH]{$srcaddr}) {
						$adj{$dstaddr}[IN_EDGE] ++;
						$adj{$srcaddr}[OUT_EDGE] ++;
					}

					$adj{$dstaddr}[NEIGH]{$srcaddr}[0] ++;
					$adj{$dstaddr}[NEIGH]{$srcaddr}[$index]{$$names[$i]} = $$data[0][$i];
				}
			}
		}
	}

	return ($start, $step);
}

sub full_url0 {
	return "$url?dst=$dst&amp;src=$src";
}

sub full_url {
	$type ||= 'ttl';
	return "$url?dst=$dst&amp;src=$src&amp;type=$type";
}

sub parse_dump_file {
	my ($dump) = @_;

	my $parser = new XML::Parser(Style => 'Tree');
	$parser->setHandlers(Start => \&start_handler);
	my $tree = $parser->parsefile($dump);

	$ended_parsing_dump = [gettimeofday];
}

sub last_dump_update {
	return (stat($dumpfile))[9];
}

sub check_outdated_dump {
	my $last_update_time = last_dump_update;

	if ($last_update_time + ($dump_update_delay * 2) < time) {
		return $last_update_time;
	} else {
		return 0;
	}
}

sub beacon_name {
	my ($d) = @_;

	return $adj{$d}[NAME] or "($d)";
}

sub make_history_url {
	my ($dst, $src, $type) = @_;

	my $dstbeacon = $dst->[0];
	my $srcbeacon = $src->[0];

	$dstbeacon =~ s/\/\d+$//;
        $srcbeacon =~ s/\/\d+$//;

	return "$url?history=1&amp;src=" . $dst->[1] . "-$dstbeacon.$type&amp;dst=" . $src->[1] . "-$srcbeacon";
}

sub build_name {
	my ($a) = @_;

	return [$a, $adj{$a}[NAME]];
}

sub make_history_link {
	my ($dst, $src, $type, $txt, $class) = @_;

	if ($history_enabled) {
		my $dstname = build_name($dst);
		my $srcname = build_name($src);
		print '<a class="', $class, '" href="', make_history_url($dstname, $srcname, $type) . '"';
		print ' title="', $srcname->[1], ' <- ', $dstname->[1], '"' if $matrix_link_title;
		print '>', $txt, '</a>';
	} else {
		print $txt;
	}
}

sub make_matrix_cell {
	my ($dst, $src, $type, $txt, $class) = @_;

	if (not defined($txt)) {
		print '<td class="noinfo_', $type, '">-</td>';
	} else {
		print '<td class="A_', $type, '">';
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
		$res .= sprintf " %id", $tm / 86400;
		$tm = $tm % 86400;
		$dosecs = 0;
	}

	if ($tm > 3600) {
		$res .= sprintf " %ih", $tm / 3600;
		$tm = $tm % 3600;
	}

	if ($tm > 60) {
		$res .= sprintf " %im", $tm / 60;
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

	if ($tag eq 'group') {
		$sessiongroup = $atts{'addr'};
		$ssm_sessiongroup = $atts{'ssmgroup'};
	} elsif ($tag eq 'beacon') {
		$current_beacon = $atts{'addr'};
		$current_source = '';

		if ($atts{'addr'} and $atts{'name'} and $atts{'age'} > 0) {
			$adj{$current_beacon}[NAME] = $atts{'name'};
			$adj{$current_beacon}[CONTACT] = $atts{'contact'};
			$adj{$current_beacon}[AGE] = $atts{'age'};
			$adj{$current_beacon}[COUNTRY] = $atts{'country'} if defined $atts{'country'};
			$adj{$current_beacon}[RX_LOCAL] = $atts{'rxlocal'} if defined $atts{'rxlocal'};
		}
	} elsif ($tag eq 'asm' or $tag eq 'ssm') {
		foreach my $att qw(ttl loss delay jitter) {
			if (defined $atts{$att}) {
				my $index = $tag eq 'ssm' ? 2 : 1;

				if (not defined $adj{$current_beacon}[NEIGH]{$current_source}) {
					$adj{$current_beacon}[IN_EDGE] ++;
					$adj{$current_source}[OUT_EDGE] ++;
				}

				$adj{$current_beacon}[NEIGH]{$current_source}[0] ++;
				$adj{$current_beacon}[NEIGH]{$current_source}[$index]{$att} = $atts{$att};
			}
		}
	} elsif ($tag eq 'source') {
		$current_source = $atts{'addr'};

		if (defined $atts{'name'} and defined $atts{'addr'}) {
			$adj{$current_source}[NAME] = $atts{'name'} if defined $atts{'name'};
			$adj{$current_source}[CONTACT] = $atts{'contact'} if defined $atts{'contact'};
			$adj{$current_source}[COUNTRY] ||= $atts{'country'} if defined $atts{'country'};
		}
	} elsif ($tag eq 'website') {
		if ($atts{'type'} ne '' and $atts{'url'} ne '') {
			if ($atts{'type'} eq 'generic') {
				$adj{$current_source or $current_beacon}[URL] = $atts{'url'};
			} elsif ($atts{'type'} eq 'lg') {
				$adj{$current_source or $current_beacon}[LG] = $atts{'url'};
			} elsif ($atts{'type'} eq 'matrix') {
				$adj{$current_source or $current_beacon}[MATRIX] = $atts{'url'};
			}
		}
	} elsif ($tag eq 'flag') {
		if ($atts{'name'} eq 'SSMPing' and $atts{'value'} eq 'true') {
			$adj{$current_beacon}[SSM_PING] = 1;
		}
	}
}

sub start_document {
	my ($additionalinfo) = @_;

	start_base_document();

	print '<h1 style="margin: 0">', $title, '</h1>', "\n";

	print '<p style="margin: 0"><small>Current server time is ', localtime() . $additionalinfo, '</small></p>', "\n";
}

sub build_header {
	my ($attname, $atthideinfo, $attwhat, $full_matrix, $show_lastupdate, $start, $step) = @_;

	if (defined $step) { # From history
		print "<p><b>Snapshot stats at " . localtime($start) . "</b> ($step seconds average)</p>\n";

		print '<form id="timenavigator" action=";">';
		print '<script type="text/javascript">
			function move(way) {
				var timenavoff = document.getElementById("timenavigator").offset;
				var selectedvalue = timenavoff.options[timenavoff.selectedIndex].value;
				var newdate = ' . $at . ' + selectedvalue * way;
				var url = "' . "$url?what=$attwhat&amp;tt=$attname" . '&amp;ammount=" + selectedvalue + "&amp;at="+newdate;
				location.href = url;
			}
			</script>';

		print '<p>Time navigation: ';
		print '<a href="javascript:move(-1)"><small>Move backward</small> &lt;</a>';

		print '<select name="offset" style="margin-left: 0.5em; margin-right: 0.5em">'."\n";

		my $ammount = $page->param('ammount');
		$ammount ||= 60;

		my @ammounts = ([60, '60 s'], [600, '10m'], [3600, '60m'], [14400, '4h'], [43200, '12h'], [86400, '24h'], [604800, '7d'], [2592000, '30d']);
		# 7884000 3 months

		foreach my $ammitem (@ammounts) {
			print '<option value="' . $ammitem->[0] . '"';
			print ' selected="selected"' if $ammitem->[0] == $ammount;
			print '> ' . $ammitem->[1] . '</option>';
		}

		print "</select>";

		print '<a href="javascript:move(1)">&gt; <small>Move forward</small></a>';
		print '</p></form>';

	} else {
		my $last_update = last_dump_update;

		print '<p><b>Current stats for</b> <code>', $sessiongroup, '</code>';
		print ' (SSM: <code>', $ssm_sessiongroup, '</code>)' if $ssm_sessiongroup;
		print ' <small>[Last update: ', format_date(time - $last_update), ' ago]</small>' if $show_lastupdate;

		my $last_update_time = check_outdated_dump;
		print '<font color="#ff0000">Warning: outdated informations, last dump was updated ' . localtime($last_update_time) . "</font><br />\n" if $last_update_time;
		print '</p>';
	}

	my $hideatt;

	$hideatt = 'hideinfo=1&amp;' if $atthideinfo;

	my $whatatt = "what=$attwhat&amp;";
	my $fullatt = "full=$full_matrix&amp;";

	my @view = qw(ttl loss delay jitter);
	my @view_name = ('TTL', 'Loss', 'Delay', 'Jitter');
	my @view_type = ('hop count', 'percentage', 'ms', 'ms');

	my $view_len = scalar(@view);
	my $i;

	print '<p style="margin: 0"><span style="float: left"><b>View</b>';

	do_faq_qlink('views');

	$attname ||= '';
	$hideatt ||= '';
	$at ||= '';

	print ' <small>(';

	if (not $atthideinfo) {
		print "<a href=\"$url?hideinfo=1&amp;$fullatt$whatatt&amp;att=$attname&amp;at=$at\">Hide Source Info</a>";
	} else {
		print "<a href=\"$url?hideinfo=0&amp;$fullatt$whatatt&amp;att=$attname&amp;at=$at\">Show Source Info</a>";
	}

	print ", <a href=\"$url?$hideatt&amp;$whatatt&amp;att=$attname&amp;at=$at&amp;full=" . (!$full_matrix) . '">' . ($full_matrix ? 'Condensed' : 'Full') . '</a>';

	if ($attwhat eq "asm") {
		print ", <a href=\"$url?$hideatt$fullatt&amp;what=both&amp;att=$attname&amp;at=$at\">ASM and SSM</a>";
		print ", <a href=\"$url?$hideatt$fullatt&amp;what=ssmorasm&amp;att=$attname&amp;at=$at\">SSM or ASM</a>";
	} elsif ($attwhat eq "ssmorasm") {
		print ", <a href=\"$url?$hideatt$fullatt&amp;what=both&amp;att=$attname&amp;at=$at\">ASM and SSM</a>";
		print ", <a href=\"$url?$hideatt$fullatt&amp;what=asm&amp;att=$attname&amp;at=$at\">ASM only</a>";
	} else {
		print ", <a href=\"$url?$hideatt$fullatt&amp;what=ssmorasm&amp;att=$attname&amp;at=$at\">SSM or ASM</a>";
		print ", <a href=\"$url?$hideatt$fullatt&amp;what=asm&amp;att=$attname&amp;at=$at\">ASM only</a>";
	}

	print ')</small>:</span></p>';

	print '<ul id="view" style="float: left">', "\n";
	for ($i = 0; $i < $view_len; $i++) {
		my $att = $view[$i];
		my $attn = $view_name[$i];
		print '<li>';
		if ($attname eq $att) {
			print '<span class="viewitem" id="currentview">', $attn, '</span>';
		} else {
			print "<a class=\"viewitem\" href=\"$url?$hideatt$fullatt$whatatt" . "att=$att&amp;at=$at\">$attn</a>";
		}
		print ' <small>(', $view_type[$i], ')</small></li>', "\n";
	}
	print '</ul>', "\n";

	print '<p style="margin: 0; margin-bottom: 1em">&nbsp;</p>';
}

sub end_document {
	print '<hr />', "\n";

	if ($debug) {
		my $render_end = [gettimeofday];
		my $diff = tv_interval $load_start, $render_end;

		print '<p style="margin: 0"><small>Took ', (sprintf "%.3f", $diff), ' seconds from load to end of render';
		if (defined($ended_parsing_dump)) {
			my $dumpdiff = tv_interval $load_start, $ended_parsing_dump;
			print ' (', (sprintf "%.3f", $dumpdiff), ' in parsing dump file)';
		}
		print '.</small></p>', "\n";
	}

	print '<p style="margin: 0"><small>matrix.pl - a tool for dynamic viewing of ', $dbeacon, ' information and history.';
	print 'by Hugo Santos, Sebastien Chaumontet and Hoerdt Mickaël</small></p>', "\n";

	print '</body>', "\n";
	print '</html>', "\n";
}

sub make_ripe_search_url {
	my ($ip) = @_;

	return "http://www.ripe.net/whois?form_type=simple&amp;full_query_string=&amp;searchtext=$ip&amp;do_search=Search";
}

sub do_faq_link {
	my ($txt, $ctx) = @_;

	if ($faq_page) {
		print ' <a style="text-decoration: none" href="', $faq_page, '#', $ctx;
		print '">', $txt, '</a>';
	} else {
		print $txt;
	}
}

sub do_faq_qlink {
	my $ctx = shift;

	return do_faq_link('<small>[?]</small>', $ctx);
}

sub render_matrix {
	my ($start, $step) = @_;

	my $attname = $page->param('att');
	my $atthideinfo = $page->param('hideinfo');
	my $attwhat = $page->param('what');
	my $full_matrix = $page->param('full');
	my $show_lastupdate = $page->param('showlastupdate');

	$attname ||= 'ttl';
	$atthideinfo ||= $default_hideinfo;
	$attwhat ||= $default_what;
	$full_matrix ||= $default_full_matrix;

	my $what_td = "colspan=\"2\"";

	$what_td = '' if $attwhat eq 'asm' or $attwhat eq 'ssmorasm';

	my $attat = $page->param('at');
	$attat = 0 if not defined $attat or $attat eq '';

	my $addinfo;
	if ($attat > 0) {
		$addinfo = " (<a href=\"$url?what=$attwhat&amp;att=$attname\">Live stats</a>)";
	} elsif ($history_enabled) {
		$addinfo = " (<a href=\"$url?what=$attwhat&amp;att=$attname&amp;at=" . (time - 60) ."\">Past stats</a>)"
	}

	start_document($addinfo);

	build_header($attname, $atthideinfo, $attwhat, $full_matrix, $show_lastupdate, $start, $step);

	my $c;
	my $i = 1;
	my @problematic = ();
	my @warmingup = ();
	my @localnoreceive = ();
	my @repnosources = ();
	my @lowrx = ();
	my @rx = ();
	my @tx = ();

	my %ids;

	print '<table border="0" cellspacing="0" cellpadding="0" class="adjr" id="adj">', "\n";
	print '<tr><td>&nbsp;</td>';

	my @sortedkeys = sort { $adj{$b}[AGE] <=> $adj{$a}[AGE] } keys %adj;

	foreach $c (@sortedkeys) {
		$ids{$c} = 0;

		$adj{$c}[IN_EDGE] ||= 0;
		$adj{$c}[OUT_EDGE] ||= 0;

		if (defined($adj{$c}[AGE]) and $adj{$c}[AGE] < 30) {
			push (@warmingup, $c);
		} elsif (not $adj{$c}[IN_EDGE] and not $adj{$c}[OUT_EDGE]) {
			push (@problematic, $c);
		} else {
			print '<td ', $what_td, '><b>S', $i, '</b></td>' if $adj{$c}[OUT_EDGE] > 0;

			$ids{$c} = $i;
			$i++;

			if (not $full_matrix) {
				if (not $adj{$c}[IN_EDGE]) {
					if ($adj{$c}[RX_LOCAL] ne 'true') {
						push (@localnoreceive, $c);
					} else {
						push (@repnosources, $c);
					}
				} elsif (($adj{$c}[IN_EDGE] / scalar(@sortedkeys)) < 0.2 and $adj{$c}[IN_EDGE] < 6) {
					push (@lowrx, $c);
				} else {
					push (@rx, $c);
				}

				push (@tx, $c) if $adj{$c}[OUT_EDGE] > 0;
			} else {
				push (@rx, $c);
				push (@tx, $c);
			}
		}
	}

	print "</tr>\n";

	foreach $a (@rx) {
		print '<tr>';
		print '<td align="right" class="beacname">', beacon_name($a), ' <b>R', $ids{$a}, '</b></td>';
		foreach $b (@tx) {
			if ($b ne $a and defined $adj{$a}[NEIGH]{$b}) {
				my $txt = $adj{$a}[NEIGH]{$b}[1]{$attname};
				my $txtssm = $adj{$a}[NEIGH]{$b}[2]{$attname};

				if ($attname ne 'ttl') {
					$txt = sprintf "%.1f", $txt if defined $txt;
					$txtssm = sprintf "%.1f", $txtssm if defined $txtssm;
				}

				if ($attwhat eq 'asm' or $attwhat eq 'ssmorasm') {
					my $whattype = 'asm';
					my $cssclass = 'AAS';
					if ($attwhat eq 'ssmorasm') {
						if (defined $txtssm) {
							if (not defined $txt) {
								$cssclass = 'AS';
							}
							$txt = $txtssm;
							$whattype = 'ssm';
						} elsif (defined $txt) {
							$cssclass = 'AA';
						}
					}

					if (not defined $txt) {
						print '<td ', $what_td, ' class="blackhole">XX</td>';
					} else {
						print '<td class="', $cssclass, '">';
						make_history_link($b, $a, $whattype, $txt, 'historyurl');
						print '</td>';
					}
				} else {
					if (not defined $txt and not defined $txtssm) {
						print '<td ', $what_td, ' class="blackhole">XX</td>';
					} else {
						make_matrix_cell($b, $a, 'asm', $txt, 'historyurl');
						make_matrix_cell($b, $a, 'ssm', $txtssm, 'historyurl');
					}
				}
			} elsif ($a eq $b) {
				print '<td ', $what_td, ' class="corner">&nbsp;</td>';
			} elsif ($full_matrix and $adj{$a}[RX_LOCAL] ne 'true') {
				print '<td ', $what_td, ' class="noreport">N/R</td>';
			} else {
				print '<td ', $what_td, ' class="blackhole">XX</td>';
			}
		}
		print '</tr>', "\n";
	}
	print '</table>', "\n";

	if (scalar(@repnosources) > 0) {
		print '<h4 style="margin-bottom: 0">Beacons that report no received sources';
		do_faq_qlink('nosources');
		print '</h4>', "\n";
		print '<ul>', "\n";
		foreach $a (@repnosources) {
			print '<li><b>R', $ids{$a}, '</b> ', beacon_name($a);
			print ' (', $adj{$a}[CONTACT], ')' if $adj{$a}[CONTACT];
			print '</li>', "\n";
		}
		print '</ul>', "\n";
	}

	if (scalar(@lowrx) > 0) {
		print '<h4 style="margin-bottom: 0">Beacons that report only a small number of received sources';
		do_faq_qlink('lowsources');
		print '</h4>', "\n";
		print '<ul>', "\n";
		foreach $a (@lowrx) {
			print '<li><b>R', $ids{$a}, '</b> ', beacon_name($a);

			print ' <small>Receives</small> { ';

			my $first = 1;

			foreach $b (keys %{$adj{$a}[NEIGH]}) {
				print ', ' if not $first;
				$first = 0;
				if ($ids{$b}) {
					print '<b>S', $ids{$b}, '</b> ', beacon_name($b);
				} else {
					print '<span class="beacon">', $b;
					print ' (', $adj{$b}[NAME], ')' if $adj{$b}[NAME];
					print '</span>';
				}
			}

			print ' }';

			print '</li>', "\n";
		}
		print '</ul>', "\n";
	}

	if (scalar(@localnoreceive) > 0) {
		print '<h4 style="margin-bottom: 0">Beacons not received localy';
		do_faq_qlink('localonly');
		print '</h4>', "\n";
		print '<ul>', "\n";
		foreach $a (@localnoreceive) {
			print '<li><b>R', $ids{$a}, '</b> ', beacon_name($a);
			print ' (', $adj{$a}[CONTACT], ')' if $adj{$a}[CONTACT];
			print '</li>', "\n";
		}
		print '</ul>', "\n";
	}

	if (scalar(@warmingup) > 0) {
		print '<h4>Beacons warming up (age < 30 secs)';
		do_faq_qlink('warmingup');
		print '</h4>', "\n";
		print '<ul>', "\n";
		foreach $a (@warmingup) {
			print '<li>', $a;
			print ' (', $adj{$a}[NAME], ', ', $adj{$a}[CONTACT], ')' if $adj{$a}[NAME];
			print '</li>', "\n";
		}
		print '</ul>', "\n";
	}

	if (scalar(@problematic) ne 0) {
		print '<h4>Beacons with no connectivity</h4>', "\n";
		print '<ul>', "\n";
		my $len = scalar(@problematic);
		for (my $j = 0; $j < $len; $j++) {
			my $prob = $problematic[$j];
			my @neighs = keys %{$adj{$prob}[NEIGH]};

			print '<li>', $prob;
			if ($adj{$prob}[NAME]) {
				print ' (', $adj{$prob}[NAME];
				print ', ', $adj{$prob}[CONTACT] if $adj{$prob}[CONTACT];
				print ')';
			}

			my $ned = scalar(@neighs);
			my $k = $ned;
			if ($k > 3) {
				$k = 3;
			}

			if ($ned) {
				print '<ul>Received from:<ul>', "\n";

				for (my $l = 0; $l < $k; $l++) {
					print '<li><span class="beacon">', $neighs[$l];
					print ' (', $adj{$neighs[$l]}[NAME], ')' if $adj{$neighs[$l]}[NAME];
					print '</span></li>', "\n";
				}

				print '<li>and others</li>', "\n" if $k < $ned;

				print '</ul></ul>';
			}

			print '</li>', "\n";
		}
		print '</ul>', "\n";
	}

	if (not $atthideinfo) {
		print '<p></p>', "\n";
		print '<table border="0" cellspacing="0" cellpadding="0" class="adjr" id="adjname">', "\n";

		print '<tr><td></td><td></td><td><b>Age</b></td><td><b>Source Address</b></td>';
		print '<td><b>Admin Contact</b></td><td><b>';
		do_faq_link('L/M', 'lg_matrix');
		print '</b></td><td><b><a href="', $ssm_ping_url, '">SSM P</a>';
		print '</b></td></tr>', "\n";
		foreach $a (@sortedkeys) {
			if ($ids{$a} > 0) {
				print '<tr>', '<td align="right" class="beacname">';
				print '<a class="beacon_url" href="', $adj{$a}[URL], '">' if $adj{$a}[URL];
				print $adj{$a}[NAME];
				print '</a>' if $adj{$a}[URL];
				print ' <b>R', $ids{$a}, '</b>', '</td>';

				print '<td>';
				if ($flag_url_format ne "" and $adj{$a}[COUNTRY]) {
					print '<img src="';
					printf $flag_url_format, lc $adj{$a}[COUNTRY];
					print '" alt="', $adj{$a}[COUNTRY], '" style="vertical-align: middle; border: 1px solid black" />';
				}
				print '</td>';

				print '<td class="age">', format_date($adj{$a}[AGE]), '</td>';
				# Removing port number from id and link toward RIPE whois db
			        my $ip = $a;
			        $ip =~ s/\/\d+$//;
			        print '<td class="addr"><a href="', make_ripe_search_url($ip), '">', $ip, '</a></td>';
				print '<td class="admincontact">', ($adj{$a}[CONTACT] or '-'), '</td>';

				my $urls;
				$urls .= " <a href=\"" . $adj{$a}[LG] . "\">L</a>" if $adj{$a}[LG];
				$urls .= " <a href=\"" . $adj{$a}[MATRIX] . "\">M</a>" if $adj{$a}[MATRIX];

				print '<td class="urls">', ($urls or '-'), '</td>';

				print '<td class="infocol">';
				if ($adj{$a}[SSM_PING]) {
					print '&bull;';
				} else {
					print '&nbsp;';
				}
				print '</td>';

				print '</tr>', "\n";
			}
		}
		print '</table>', "\n";
	}

	print '<p><br />If you wish to add a beacon to your site, you may use ', $dbeacon;
	if (defined $step) {
		print '.</p>', "\n";
	} else {
		print ' with the following parameters:</p>', "\n";
		print '<p><code>./dbeacon -n NAME -b ', $sessiongroup;
		if (defined $ssm_sessiongroup) {
			print ' -S';
			print ' ', $ssm_sessiongroup if $ssm_sessiongroup ne $default_ssm_group;
		}
		print ' -a CONTACT</code></p>', "\n";
	}

	end_document;
}

sub store_data {

	if (check_outdated_dump) {
		die "Outdated dumpfile\n";
	}
	parse_dump_file(@_);

	foreach my $a (keys %adj) {
		if ($adj{$a}[NAME]) {
			foreach my $b (keys %adj) {
				if ($a ne $b and defined $adj{$a}[NEIGH]{$b}) {
					if ($adj{$b}[NAME]) {
						store_data_one($a, $adj{$a}[NAME], $b, $adj{$b}[NAME], "asm");
						store_data_one($a, $adj{$a}[NAME], $b, $adj{$b}[NAME], "ssm");
					}
				}
			}
		}
	}

	return 0;
}

sub store_data_one {
	my ($dst, $dstname, $src, $srcname, $tag) = @_;

	my $dst_h = build_host($dstname, $dst);
	my $src_h = build_host($srcname, $src);

	my %values;

	my $good = 0;

	my $index = 1;
	if ($tag eq 'ssm') {
		$index = 2;
	}

	foreach my $type qw(ttl loss delay jitter) {
		$values{$type} = $adj{$dst}[NEIGH]{$src}[$index]{$type};
		$good++ if defined $values{$type};
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
	foreach my $valuetype qw(ttl loss delay jitter) {
		# Store it in s and not ms
		$values{$valuetype} = $values{$valuetype} / 1000. if $valuetype eq 'delay' or $valuetype eq 'jitter';
		$updatestring .= ':' . $values{$valuetype};
	}

	print "Updating $dstbeacon <- $srcbeacon with $updatestring\n" if $verbose > 1;

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
	my ($msrc, undef, $asmorssm) = get_name_from_host($src);
	my ($mdst) = get_name_from_host($dst);

	my $rrdfile = build_rrd_file_path($historydir, $dst, $src, $asmorssm);

	# Escape ':' chars
	$rrdfile =~ s/:/\\:/g;

	$asmorssm =~ s/([a-z])/\u$1/g; # Convert to uppercase

	print $page->header(-type => 'image/png', -expires => '+3s');

	my $width = 450;
	my $height = 150;

	if (defined $page->param('thumb')) {
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

	if (not defined $page->param('thumb')) {
		push (@args,  '--vertical-label',$ytitle);
		push (@args, 'COMMENT:' . strftime("%a %b %e %Y %H:%M (%Z)", localtime) . ' ' . strftime("%H:%M (GMT)", gmtime).'\r');
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

	return ($1, $2, $3) if $host =~ /^(.+)\-(.+)\.(ssm|asm)$/;
	return ($1, $2) if $host =~ /^(.+)\-(.+)$/;
	return 0;
}

sub do_list_beacs {
	my ($name, $dst, $src, @vals) = @_;

	print '<select name="'.$name.'" onchange="location = this.options[this.selectedIndex].value;">'."\n";

	my $def = $name eq 'srcc' ? $src : $dst;

	foreach my $foo (@vals) {
		print '<option value="'.$url.'?history=1&amp;dst=';
		print $dst, '&amp;src=' if $name eq 'srcc';
		print $foo;
		print '"';

		print ' selected="selected"' if $foo eq $def;

		print ">" . (get_name_from_host($foo))[0];
		print ' (' . (get_name_from_host($foo))[2] . ')' if $name eq 'srcc';
		print '</option>', "\n";
	}

	print '</select>', "\n";

}

sub graphthumb {
	my ($type) = shift;
	print '<a href="' . full_url0 . "&amp;history=1&amp;type=$type\">\n";
	print '<img style="margin-right: 0.5em; margin-bottom: 0.5em; border: 0" alt="thumb" src="' . full_url0 . "&amp;type=$type&amp;img=true&amp;thumb=true&amp;age=$age\" /></a><br />\n";
}

sub list_graph {
	start_document(" (<a href=\"$url\">Live stats</a>)");

        if (defined $dst) {
               print "<p>To ";

               do_list_beacs("dstc", $dst, undef, get_beacons($historydir));

               if (defined $src) {
                       print "From ";
                       do_list_beacs("srcc", $dst, $src, get_beacons("$historydir/$dst"));

                       if (defined $type) {
                               print "Type ";

                               my @types = (["-- All --", "", ""], ["TTL", "ttl", ""], ["Loss", "loss", ""], ["Delay", "delay", ""], ["Jitter", "jitter", ""]);

				print '<select name="type" onchange="location = this.options[this.selectedIndex].value;">'."\n";

				foreach my $foo (@types) {
					print '<option value="' . full_url0 . '&amp;history=1&amp;type=' . $$foo[1].'"';
					print ' selected="selected"' if $type eq $$foo[1];
					print '>'.$$foo[0]."\n";;
				}
				print "</select>\n";
			}
		}

		print "</p>";
	}

	if (not defined $dst) {

		# List beacon receiving infos

		print '<p>Select a receiver:</p>';

		my @beacs = get_beacons($historydir);

		print "<ul>\n";

		foreach my $beac (@beacs) {
			print '<li><a href="'.$url.'?history=1&amp;dst=' . $beac . '">' . (get_name_from_host($beac))[0] . "</a></li>\n";
		}

		print "</ul>\n";

	} elsif (not defined $src) {
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

			if (defined $pairs{$key}[0]) {
				print '<a href="?history=1&amp;dst=' . $dst . '&amp;src=' . $pairs{$key}[0] . '">';
			}

			print ((get_name_from_host($key))[0]);

			if (defined $pairs{$key}[0]) {
				print '</a>';
			}

			if (defined $pairs{$key}[1]) {
				print ' / <a href="?history=1&amp;dst='.$dst.'&amp;src=' . $pairs{$key}[1] . "\">SSM</a>";
			}

			print "</li>\n";
		}
		print "</ul>\n";
	}  elsif (not defined $type) {
		print "<div style=\"margin-left: 2em\">\n";
		print "<h2 style=\"margin-bottom: 0\">History for the last " . $ages{$age} . "</h2>\n";
		print "<small>Click on a graphic for more detail</small><br />\n";
		print "<table style=\"margin-top: 0.6em\">";

		my $count = 0;

		foreach my $type qw(ttl loss delay jitter) {
			print '<tr>' if ($count % 2) == 0;
			print '<td>';
			graphthumb($type);
			print '</td>', "\n";
			print '</tr>', "\n" if ($count %2) == 1;
			$count++;
		}

		print "</table>\n";

		print '<p>Last: ';

		foreach my $agen (@propersortedages) {
			print " <a href=\"" . full_url0 . "&amp;history=1&amp;age=" . $agen . "\">" . $ages{$agen} . "</a>";
		}

		print "</p>\n";
		print "</div>\n";
	} else {
		print "<br />";
		print "<div style=\"margin-left: 2em\">\n";
		# Dst, src and type selected => Displaying all time range graphs
		foreach my $age ('-1d','-1w','-1m','-1y') {
			print "<img style=\"margin-bottom: 0.5em\" src=\"" . full_url . "&amp;age=$age&amp;img=true\" /><br />";
		}
		print "</div>";
	}

	end_document;
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
table#adj td.AAS, table#adj td.A_asm, table#adj td.A_ssm {
	background-color: #96ef96;
}

table#adj td.AA {
	background-color: #c0ffc0;
}

table#adj td.AS {
	background-color: #96d396;
}

table#adj td.noreport {
	background-color: #ccc;
}

table#adj td.blackhole {
	background-color: #000000;
}

table#adj td.corner {
	background-color: #dddddd;
}

table#adj td.A_asm {
	border-right: 0.075em solid white;
}

table#adj td.noreport, td.blackhole, td.AAS, td.AS, td.AA, td.A_ssm, td.corner {
	border-right: 0.2em solid white;
}

table#adjname td.addr, table#adjname td.admincontact, table#adjname td.age, table#adjname td.urls, td.infocol {
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

#view #currentview {
	border-bottom: 1px solid #d4d4d4;
}

a {
	color: Blue;
	border-bottom: 1px solid #b0b0b0;
	text-decoration: none;
}

a:visited {
	color: Blue;
	border-bottom: 1px solid #b0b0b0;
	text-decoration: none;
}

a:hover {
	border-bottom: 1px solid Blue;
	text-decoration: none;
}

a.historyurl, a.historyurl:visited {
	color: black;
	text-decoration: none;
	border: 0;
}

\t</style>";
}

