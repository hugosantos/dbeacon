#!/usr/bin/perl

# history.pl - a CGI to create on the fly html pages and graphs from some rrd file filled thanks to arch.pl
#
# To use it you can add this line in your apache config file:
# ScriptAlias /matrix/history/ /home/seb/dbeacon/contrib/history/history.pl
#
# Originally by Sebastien Chaumontet

use strict;
use RRDs;
use CGI;
use Switch;
use POSIX qw(strftime);

our $historydir;

# Assign default values
$historydir = 'data';

# Load perl config script which should overide default parameter
do("history.conf");

$|=1; # Do not bufferize STDOUT

my $page = new CGI;
my $url = $page->script_name();

my $dst = $page->param('dst');
my $src = $page->param('src');
my $type = $page->param('type');
my $age = $page->param('age');

my %ages = (
	"-1h" => "Hour",
	"-6h" => "6 Hours",
	"-12h" => "12 Hours",
	"-1d" => "Day",
	"-1w" => "Week",
	"-1m" => "Month",
	"-1y" => "Year");

my @propersortedages = ("-1m", "-1w", "-1d", "-12h", "-6h", "-1h");

if (not defined($ages{$age})) {
	$age = '-1d';
}

sub full_url0 {
	return "$url?dst=$dst&src=$src";
}

sub full_url {
	return "$url?dst=$dst&src=$src&type=$type";
}

sub get_beacons {
	my ($target, $isf, $start) = @_;

	opendir (DIR, $target) or die "Failed to open directory $target\n";
	my @res = ();

	foreach my $dircontent (readdir(DIR)) {
		if ($dircontent ne "." and $dircontent ne ".." and
			(($isf and -f "$target/$dircontent") or (not $isf and -d "$target/$dircontent"))) {
			my $dst = $dircontent;
			my $final = "$target/$dircontent";
			if ($isf) {
				$dst =~ s/\.rrd$//;
				my $simname = $dst;
				$simname =~ s/^(.+)\..+\.(.+)$/$1/;
				my $name = $dst;
				$name =~ s/^(.+)\..+\.(.+)$/$1 ($2)/;
				push (@res, [$name, $dst, "$start$dst", $final, $simname, $2 eq "ssm"]);
			} else {
				$dst =~ s/^(.+)\..+$/$1/;
				push (@res, [$dst, $dircontent, "$start$dircontent", $final]);
			}
		}
	}

	close (DIR);

	return @res;
}

sub get_dstbeacons {
	return get_beacons($historydir, 0, "$url?dst=");
}

sub get_srcbeacons {
	my ($dst) = @_;
	return get_beacons("$historydir/$dst", 1, "$url?dst=$dst&src=");
}

sub listgraph {
	start_document();

	if (defined($dst)) {
		print "To ";

		do_list_beacs("dstc", $dst, (["-- Initial Page --", "", "$url"], get_dstbeacons()));

		if (defined($src)) {
			print "From ";
			do_list_beacs("srcc", $src, (["-- Source List --", "", "$url?dst=$dst"], get_srcbeacons($dst)));

			if ($type ne "") {
				print "Type ";

				my @types = (["-- All --", "", ""], ["TTL", "ttl", ""], ["Loss", "loss", ""], ["Delay", "delay", ""], ["Jitter", "jitter", ""]);

				foreach my $type (@types) {
					$type->[2] = full_url0() . '&type=' . $type->[1];
				}

				do_list_beacs("typec", $type, @types);
			}
		}

		print "<br />";
	}

	if (!defined($dst)) {
		# List beacon receiving infos

		print 'Select a receiver:';

		my @beacs = get_dstbeacons();

		print "<ul>\n";

		foreach my $beac (@beacs) {
			print '<li><a href="' . $beac->[2] . '">' . $beac->[0] . "</a></li>\n";
		}

		print "</ul>\n";

	} elsif (!defined($src)) {
		print '<br />Select a source:';

		# List visible src for this beacon

		my @beacs = get_srcbeacons($dst);

		my %pairs;

		# indexing is being done by name only, should be name+addr, needs fixing -hugo

		foreach my $beac (@beacs) {
			if (not defined($pairs{$beac->[4]})) {
				$pairs{$beac->[4]} = [undef, undef];
			}

			if ($beac->[5]) {
				$pairs{$beac->[4]}->[1] = $beac->[2];
			} else {
				$pairs{$beac->[4]}->[0] = $beac->[2];
			}
		}

		print "<ul>\n";
		foreach my $key (keys %pairs) {
			print "<li>";

			if (defined($pairs{$key}->[0])) {
				print '<a href="' . $pairs{$key}->[0] . '">';
			}

			print $key;

			if (defined($pairs{$key}->[0])) {
				print '</a>';
			}

			if (defined($pairs{$key}->[1])) {
				print ' / <a href="' . $pairs{$key}->[1] . "\">SSM</a>";
			}

			print "</li>\n";
		}
		print "</ul>\n";

	} elsif ($type eq "") {
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
			print " <a href=\"" . full_url0() . "&age=" . $agen . "\">" . $ages{$agen} . "</a>";
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

sub do_list_beacs {
	my ($name, $def, @vals) = @_;

	print "<select name=\"$name\" onChange=\"location = this.options[this.selectedIndex].value;\">\n";

	foreach my $foo (@vals) {
		print "<option value=\"" . $foo->[2] . "\"";
		if ($foo->[1] eq $def) {
			print " selected";
		}
		print ">" . $foo->[0] . "</option>\n";
	}

	print "</select>\n";

}

sub graphthumb {
	my ($type) = shift @_;
	print "<a href=\"" . full_url0() . "&type=$type\">";
	print "<img style=\"margin-right: 0.5em; margin-bottom: 0.5em\" border=\"0\" src=\"" . full_url0() . "&type=$type&img=true&thumb=true&age=$age\" /></a><br />";
}

sub graphgen {
	my $title;
	my $ytitle;
	my $unit;
	switch ($type) {
		case "ttl"	{ $title='TTL'   ; $ytitle='Hops'; $unit='%3.0lf hops' }
		case "loss"	{ $title='Loss'  ; $ytitle='% of packet loss'; $unit='%2.1lf %%' }
		case "delay"	{ $title='Delay' ; $ytitle='Seconds'; $unit='%2.2lf %ss' }
		case "jitter"	{ $title='Jitter'; $ytitle='Seconds'; $unit='%2.2lf %ss' }
		else		{ die "Unknown type\n"; }
	}

	# Display only the name
	my $msrc = $src;
	my $mdst = $dst;

	$msrc =~ s/^(.+)\..+\.(.+)$/$1/;
	my $asmorssm = $2;
	$asmorssm =~ s/([a-z])/\u$1/g; # Convert to uppercase

	$mdst =~ s/^(.+)\..+$/$1/;

	# Escape ':' chars
	my $rrdfile = "$historydir/$dst/$src.rrd";
	$rrdfile =~ s/:/\\:/g;

	print $page->header(-type => 'image/png', -expires => '+3s');

	my $width = 450;
	my $height = 150;

	if ($page->param('thumb') eq "true") {
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

	if ($page->param('thumb') ne "true") {
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

sub start_document {
	print $page->header;

	print "<html>
<head>
<title>IPv6 Multicast Beacon History</title>

<meta http-equiv=\"refresh\" content=\"60\" />

<style type=\"text/css\">
body {
	font-family: Verdana, Arial, Helvetica, sans-serif;
	font-size: 100%;
}
</style>
</head>
<body>
<h1>IPv6 Multicast Beacon history</h1>\n";
}

sub end_document {
	print "<hr />\n";

	print "<small>history.pl - a history backend for dbeacon. by Sebastien Chaumontet and Hugo Santos</small>\n";

	print "</body></html>";
}

if (defined($dst) and defined($src) and defined($type) and $page->param('img') eq "true") {
	graphgen();
} else {
	listgraph();
}

