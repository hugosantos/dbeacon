#!/usr/bin/perl -w

# arch.pl - read dbeacon dump file and fill related rrds
# use history.pl to see data
#
# You can start arch.pl from crontab with a line like: 
# * * * * * cd /home/seb/dbeacon/contrib/history/ ; ./arch.pl > arch.log 2>&1 
#
# Originally by Sebastien Chaumontet
# Lot of lines are comming from Hoerdt Micka<EB>l's matrix.pl

# -------- Configurable part

# Where dbeacon is generating its dump?
my $dumpfile = "../../dump.xml";
# to use with dbeacon -L
#my $dumpfile = shift @ARGV;

# In which directory rrd are stored
my $historydir = "data";

# --------- End of configurable part

use strict;
use XML::Parser;
use RRDs;


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
		my %values;
		foreach my $valuetype ('ttl','loss','delay','jitter')
		{
			if ($atts{$valuetype})
			{
				$values{$valuetype} = $atts{$valuetype};
			}
			else
			{
				return;
			}
		}
		if ($values{'ttl'} and $values{'loss'} and $values{'delay'} and $values{'jitter'})
		{
			storedata($dstbeacon,$srcbeacon,$tag,%values);
		}
	}
}

sub storedata {
	my ($dstbeacon,$srcbeacon,$asmorssm,%values) = @_;

	# Removing port number as it change between two beacon restarts
        $dstbeacon =~ s/\/\d+$//;
        $srcbeacon =~ s/\/\d+$//;

	# Removing bad chars in name
        $dstbeacon =~ s/[^A-z0-9\:\.\-_\s]//g;
        $srcbeacon =~ s/[^A-z0-9\:\.\-_\s]//g;

	if (! -f "$historydir/$dstbeacon/$srcbeacon.$asmorssm.rrd")
	{
		print "New combination; Rrd file $historydir/$dstbeacon/$srcbeacon.$asmorssm.rrd need to be crated\n";
		if (! -d "$historydir/$dstbeacon")
		{
			print "Creating dir $historydir/$dstbeacon/\n";
			mkdir "$historydir";
			if (! mkdir "$historydir/$dstbeacon")
			{
				die "Unable to create $historydir/$dstbeacon/ directory: $!";
			}
		}
		if (!RRDs::create("$historydir/$dstbeacon/$srcbeacon.$asmorssm.rrd",
			'-s 60', 			# steps in seconds
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
			'RRA:MAX:0.5:120:8784'))
		{
			die(RRDs::error);
		}
	}

	# Update rrd with new values

	my $updatestring = 'N';
	foreach my $valuetype ('ttl','loss','delay','jitter')
	{
		if ($valuetype eq 'delay' or $valuetype eq 'jitter')
		{ # Store it in s and not ms
			$values{$valuetype} = $values{$valuetype}/1000;
		}
		$updatestring.=':'.$values{$valuetype};
	}
	if (!RRDs::update("$historydir/$dstbeacon/$srcbeacon.$asmorssm.rrd",$updatestring))
	{
		die(RRDs::error);
	}
}

