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

# Load perl config script
do("history.conf");

# Assign default values
if (!$historydir)
{
        $historydir = 'data';
}

$|=1; # Do not bufferize STDOUT

my $page = new CGI;
my $url = $page->script_name();

sub listgraph
{

print $page->header;

print "
<html>
<head>

<meta http-equiv=\"refresh\" content=\"60\" />

<style type=\"text/css\">
body {
	font-family: Verdana, Arial, Helvetica, sans-serif;
	font-size: 100%;
}


</style>
</head>
<body>
<h1>IPv6 Multicast Beacon history</h1>
";

sub get_beacons {
	my ($target, $isf) = @_;

	opendir (DIR, $target) or die "Failed to open directory $target\n";
	my @res = ();

	foreach my $dircontent (readdir(DIR)) {
		if ($dircontent ne "." and $dircontent ne ".." and
			(($isf and -f "$target/$dircontent") or (not $isf and -d "$target/$dircontent"))) {
			my $dst = $dircontent;
			my $final = "$target/$dircontent";
			if ($isf) {
				$dst =~ s/\.rrd$//;
				my $name = $dst;
				$name =~ s/^(.+)\..+\.(.+)$/$1 ($2)/;
				push (@res, [$name, $dst, $final]);
			} else {
				$dst =~ s/^(.+)\..+$/$1/;
				push (@res, [$dst, $dircontent, $final]);
			}
		}
	}

	close (DIR);

	return @res;
}

sub get_dstbeacons {
	return get_beacons($historydir, 0);
}

sub get_srcbeacons {
	my ($dst) = @_;
	return get_beacons("$historydir/$dst", 1);
}

if (!$page->param('dst'))
{
	# List beacon receiving infos

	print 'Select a receiver:<br><br>';

	opendir(DIR,$historydir) or die "trouble in opening the directory: $historydir $!\n";
	foreach my $dircontent (readdir(DIR))
	{
		if (-d $historydir.'/'.$dircontent and $dircontent ne '.' and $dircontent ne '..')
		{
			print '<a href="'.$url.'?dst='.$dircontent.'">';
			$dircontent =~ s/(.+)\.(.+)$/$1 ($2)/;
			print "$dircontent</a><br>\n";
		}
	}
	close(DIR);
}
elsif (!$page->param('src'))
{
	print 'Select a source:<br><br>';

	# List visible src for this beacon

	opendir(DIR,$historydir.'/'.$page->param('dst')) or die "trouble in opening the directory: $historydir $!\n";
	foreach my $dircontent (readdir(DIR))
	{
		if (-f $historydir.'/'.$page->param('dst').'/'.$dircontent and $dircontent and $dircontent ne '.' and $dircontent ne '..')
		{
			$dircontent =~ s/\.rrd$//;
			print '<a href="'.$url.'?dst='.$page->param('dst').'&src='.$dircontent.'">';
			$dircontent =~ s/(.+)\.(.+)\.(.+)$/$1 ($2)/;
			print "$dircontent</a> $3<br>\n";
		}
	}
	close(DIR);
}
elsif (!$page->param('type'))
{
	print "To ";
	do_list_beacs("dstc", $page->param("dst"), get_dstbeacons());
	print "From ";
	do_list_beacs("srcc", $page->param("src"), get_srcbeacons($page->param("dst")));

	print "<br /><br />";

	print "Click on a graphic for more detail<br /><br />\n";
	my $src = $page->param('src');
	my $dst = $page->param('dst');
	$src =~ s/^(.+)\..+\.(.+)$/$1/;
	$dst =~ s/^(.+)\..+$/$1/;
	print "<table>";
	print "<tr>";
	foreach my $type ("ttl", "loss") {
		print "<td>";
		graphthumb($type);
		print "</td>";
	}
	print "</tr>";
	print "<tr>";
	foreach my $type ("delay", "jitter") {
		print "<td>";
		graphthumb($type);
		print "</td>";
	}
	print "</tr>";
}
else
{
	print "To ";
	do_list_beacs("dstc", $page->param("dst"), get_dstbeacons());
	print "From ";
	do_list_beacs("srcc", $page->param("src"), get_srcbeacons($page->param("dst")));
	print "Type ";
	do_list_beacs("typec", $page->param("type"), (["TTL", "ttl"], ["Loss", "loss"], ["Delay", "delay"], ["Jitter", "jitter"]));

	print "<br /><br />";

	# Dst, src and type selected => Displaying all time range graphs
	foreach my $age ('-1d','-1w','-1m','-1y')
	{
		print '<img src="'.$url.'?dst='.$page->param('dst').'&src='.$page->param('src').'&type='.$page->param('type').'&age='.$age.'&img=true"><br>';
	}
}



print "
</body>
<html>
";
}

sub do_list_beacs {
	my ($name, $def, @vals) = @_;

	print "<select name=\"$name\">\n";

	foreach my $foo (@vals) {
		print "<option value=\"" . $foo->[1] . "\"";
		if ($foo->[1] eq $def) {
			print " selected";
		}
		print ">" . $foo->[0] . "</option>\n";
	}

	print "</select>\n";

}

sub graphthumb {
	my ($type) = shift @_;
	print '<a href="'.$url.'?dst='.$page->param('dst').'&src='.$page->param('src').'&type='.$type.'">';
	print '<img border="0" src="'.$url.'?dst='.$page->param('dst').'&src='.$page->param('src').'&type='.$type.'&img=true&thumb=true"></a><br>';
}

sub graphgen
{
	my $age;
	if ($page->param('age'))
	{
		$age = $page->param('age');
	}
	else
	{
		$age = '-1d';
	}

	my $title;
	my $ytitle;
	my $unit;
	switch ($page->param('type'))
	{
		case "ttl"	{ $title='TTL'   ; $ytitle='Hops'; $unit='%3.0lf hops' }
		case "loss"	{ $title='Loss'  ; $ytitle='% of packet loss'; $unit='%2.1lf %%' }
		case "delay"	{ $title='Delay' ; $ytitle='Seconds'; $unit='%2.2lf s' }
		case "jitter"	{ $title='Jitter'; $ytitle='Seconds'; $unit='%2.2lf s' }
		else		{ die "Unknown type\n"; }
	}

	# Display only the name
	my $src = $page->param('src');
	my $dst = $page->param('dst');

	$src =~ s/^(.+)\..+\.(.+)$/$1/;
	my $asmorssm = $2;
	$asmorssm =~ s/([a-z])/\u$1/g; # Convert to uppercase

	$dst =~ s/^(.+)\..+$/$1/;

	# Escape ':' chars
	my $rrdfile = $historydir.'/'.$page->param('dst').'/'.$page->param('src').'.rrd';
	$rrdfile =~ s/:/\\:/g;

	print $page->header(-type=>'image/png',-expires=>'+3s');

	my $width = 450;
	my $height = 150;

	if ($page->param('thumb') eq "true") {
		$width = 300;
		$height = 100;
		$title .= " ($ytitle)";
	} else {
		$title.= " from $src to $dst ($asmorssm)";
	}

	my @args = ('-',
		'--imgformat', 'PNG',
		'--start',$age,
		'--width=' . $width,
		'--height=' . $height,
		'--title='.$title,
		'DEF:Max='.$rrdfile.':'.$page->param('type').':MAX',
		'DEF:Avg='.$rrdfile.':'.$page->param('type').':AVERAGE',
		'DEF:Min='.$rrdfile.':'.$page->param('type').':MIN',
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
		push (@args, 'GPRINT:Min:AVERAGE:'.$unit);
	} else {
		push (@args, 'AREA:Avg#CC0000:Avg');
		push (@args, 'GPRINT:Avg:AVERAGE:'.$unit);
	}

	push (@args, 'GPRINT:Max:LAST:Last '.$unit.'\n');

	if (!RRDs::graph(@args)) {
		die(RRDs::error);
  	}
}


if ($page->param('dst') and $page->param('src') and $page->param('type') and $page->param('img'))
{
  graphgen();
}
else
{
  listgraph();
}
