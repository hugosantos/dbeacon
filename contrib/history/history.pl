#!/usr/bin/perl

# history.pl - a CGI to create on the fly html pages and graphs from some rrd file filled thanks to arch.pl
#
# To use it you can add this line in your apache config file:
# ScriptAlias /matrix/history/ /home/seb/dbeacon/contrib/history/history.pl
#
# Originally by Sebastien Chaumontet

# -------- Configurable part

# In which directory rrd are stored
my $historydir = "data";

# -------- End of configurable part

use strict;
use RRDs;
use CGI;
use Switch;
use POSIX qw(strftime);

my $page = new CGI;

sub listgraph
{
my $url = $page->script_name();

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
	print 'Select value you want to display:<br><br>';
	# Dst and src selected => Displaying daily graphs of all types
	foreach my $type  ('ttl','loss','delay','jitter')
	{
		print '<a href="'.$url.'?dst='.$page->param('dst').'&src='.$page->param('src').'&type='.$type.'">';
		print '<img border="0" src="'.$url.'?dst='.$page->param('dst').'&src='.$page->param('src').'&type='.$type.'&img=true"></a><br>';
	}
}
else
{
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

	$title.= " from $src to $dst ($asmorssm)";

	# Escape ':' chars
	my $rrdfile = $historydir.'/'.$page->param('dst').'/'.$page->param('src').'.rrd';
	$rrdfile =~ s/:/\\:/g;

	print $page->header(-type=>'image/png',-expires=>'+3s');

	if (!RRDs::graph('-',
		'--imgformat', 'PNG',
		'--start',$age,
		'--title='.$title,
		'--vertical-label',$ytitle,
		'DEF:Max='.$rrdfile.':'.$page->param('type').':MAX',
		'DEF:Avg='.$rrdfile.':'.$page->param('type').':AVERAGE',
		'DEF:Min='.$rrdfile.':'.$page->param('type').':MIN',
		'CDEF:nodata=Max,UN,INF,UNKN,IF',
		'AREA:nodata#E0E0FD',
		'AREA:Max#FF0000:Max',
		'GPRINT:Max:MAX:'.$unit,
		'AREA:Avg#CC0000:Avg',
		'GPRINT:Avg:AVERAGE:'.$unit,
		'AREA:Min#990000:Min',
		'GPRINT:Min:AVERAGE:'.$unit,
		'GPRINT:Max:LAST:Last max '.$unit.'\n',
		'COMMENT:'.strftime("%a %b %e %Y %H:%M (%Z)",localtime).' '.strftime("%H:%M (GMT)",gmtime).'\r' ))
	{
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
