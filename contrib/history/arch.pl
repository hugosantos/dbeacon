#!/usr/bin/perl -w

# arch.pl - read dbeacon dump file and fill related rrds
# use history.pl to see data
#
# You can start arch.pl from crontab with a line like:
# * * * * * cd /home/seb/dbeacon/contrib/history/ ; ./arch.pl > arch.log 2>&1
#
# Or directly from dbeacon using for instance:
# ./dbeacon [...] -L contrib/history/arch.pl
#
# Originally by Sebastien Chaumontet
# Lot of lines are comming from Hoerdt Micka<EB>l's matrix.pl

use strict;
use XML::Parser;
use RRDs;

our $dumpfile;
our $historydir;

# to use with dbeacon -L
#$dumpfile = shift @ARGV;

# Load perl config script
do("history.conf");

# Assign default values
if (!$dumpfile)
{
	$dumpfile = '../../dump.xml';
}
if (!$historydir)
{
	$historydir = 'data';
}


my $verbose = 1;

my $dstbeacon;
my $srcbeacon;

# initialize parser and read the file
my $parser = new XML::Parser(Style => 'Tree');
$parser->setHandlers(Start => \&start_handler);
my $tree = $parser->parsefile($dumpfile);

# Parser callback
sub start_handler
{
        my ($p, $tag, %atts) = @_;

	if ($tag eq "beacon")
	{
		if ($atts{"name"} and $atts{"addr"})
		{
			$dstbeacon = $atts{"name"}.'.'.$atts{"addr"};
		}
		else
		{
			$dstbeacon = undef;
		}
	}
	elsif ($tag eq "source")
	{

		if ($atts{"name"} and $atts{"addr"})
		{
			$srcbeacon = $atts{"name"}.'.'.$atts{"addr"};
		}
		else
		{
			$srcbeacon = undef;
		}
	}
	elsif ($tag eq "asm" or $tag eq "ssm")
	{
		if (defined($atts{'ttl'}) and defined($atts{'loss'}) and defined($atts{'delay'}) and defined($atts{'jitter'})) {
			if ($srcbeacon and $dstbeacon) {
				storedata($dstbeacon,$srcbeacon,$tag,%atts);
			}
		}
	}
}

sub rrd_file_path {
	my ($dstbeacon, $srcbeacon, $asmorssm) = @_;

	return "$historydir/$dstbeacon/$srcbeacon.$asmorssm.rrd";
}

sub make_rrd_file_path {
	my ($dstbeacon, $srcbeacon, $asmorssm) = @_;

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
	my ($dstbeacon, $srcbeacon, $asmorssm) = @_;

	my $rrdfile = rrd_file_path(@_);

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
	my ($dstbeacon,$srcbeacon,$asmorssm,%values) = @_;

	# Removing port number as it change between two beacon restarts
        $dstbeacon =~ s/\/\d+$//;
        $srcbeacon =~ s/\/\d+$//;

	# Removing bad chars in name
        $dstbeacon =~ s/[^A-z0-9\:\.\-_\s]//g;
        $srcbeacon =~ s/[^A-z0-9\:\.\-_\s]//g;

	check_rrd($dstbeacon, $srcbeacon, $asmorssm);

	# Update rrd with new values

	my $updatestring = 'N';
	foreach my $valuetype ('ttl','loss','delay','jitter') {
		if ($valuetype eq 'delay' or $valuetype eq 'jitter') {
			# Store it in s and not ms
			$values{$valuetype} = $values{$valuetype}/1000;
		}
		$updatestring.=':'.$values{$valuetype};
	}

	if (!RRDs::update(rrd_file_path($dstbeacon, $srcbeacon, $asmorssm), $updatestring)) {
		return 0;
	}

	return 1;
}

