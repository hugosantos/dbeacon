#!/usr/bin/perl -w

use XML::Parser;
use strict;
# configuration variables, may be changed in matrix.conf
our $dumpfile = '/home/www/matrix/dump.xml';
our $default_what = 'ssmorasm';
my %adj;
my $sessiongroup;
my $ssm_sessiongroup;
my $current_beacon;
my $current_source;

do 'matrix.conf';


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

parse_dump_file($dumpfile);
render_matrix();

sub beacon_name {
        my ($d) = @_;

	        return $adj{$d}[NAME] or "($d)";
}



sub parse_dump_file {
	my ($dump) = @_;

	my $parser = new XML::Parser(Style => 'Tree');
	$parser->setHandlers(Start => \&start_handler);
	my $tree = $parser->parsefile($dump);

}


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
			if (defined($atts{'country'})) {
				$adj{$current_beacon}[COUNTRY] = $atts{'country'};
			}
		}
	} elsif ($tag eq 'asm' or $tag eq 'ssm') {
		foreach my $att ('ttl', 'loss', 'delay', 'jitter') {
			if (defined($atts{$att})) {
				my $index = 1;
				if ($tag eq 'ssm') {
					$index = 2;
				}

				if (not defined($adj{$current_beacon}[NEIGH]{$current_source})) {
					$adj{$current_beacon}[IN_EDGE] ++;
					$adj{$current_source}[OUT_EDGE] ++;
				}

				$adj{$current_beacon}[NEIGH]{$current_source}[0] ++;
				$adj{$current_beacon}[NEIGH]{$current_source}[$index]{$att} = $atts{$att};
			}
		}
	} elsif ($tag eq 'source') {
		$current_source = $atts{'addr'};

		if (defined($atts{'name'}) and defined($atts{'addr'})) {
			if (defined($atts{'name'})) {
				$adj{$current_source}[NAME] = $atts{'name'};
			}
			if (defined($atts{'contact'})) {
				$adj{$current_source}[CONTACT] = $atts{'contact'}
			}

			if (not $adj{$current_source}[COUNTRY] and defined($atts{'country'})) {
				$adj{$current_source}[COUNTRY] = $atts{'country'};
			}
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
	}
}

sub render_matrix {

	my $attname = "ttl";
	my $attwhat = $default_what;
	my $c;
	my $i=1;
	my %ids;
	

	printf("   ASM/SSM dist. |");

	foreach $c (keys %adj) {
			if ($adj{$c}[OUT_EDGE] > 0) {
		        printf("S%-2d|",$i);
			}

			$ids{$c} = $i;
			$i++;
	}
	print "\n";

	foreach $a (keys %adj) {
		my $id = $ids{$a};
		if ($id >= 1 and $adj{$a}[IN_EDGE] > 0) {
			printf("|%-2d.%-12s |",$id,substr(beacon_name($a),0,12));	
			foreach $b (keys %adj) {
				if ($ids{$b} >= 1 and $adj{$b}[OUT_EDGE] > 0) {
					if ($b ne $a and defined($adj{$a}[NEIGH]{$b})) {
						my $txt = $adj{$a}[NEIGH]{$b}[1]{$attname};
						my $txtssm = $adj{$a}[NEIGH]{$b}[2]{$attname};

						if ($attname ne 'ttl') {
							if (defined($txt)) {
								$txt = sprintf("%.1f ", $txt);
							}
							if (defined($txtssm)) {
								$txtssm = sprintf("%.1f ", $txtssm);
							}
						}

						if ($attwhat eq "asm" or $attwhat eq "ssmorasm") {
							my $whattype = "asm";
							my $cssclass = "fulladjacent";
							if ($attwhat eq "ssmorasm") {
								if (defined($txtssm)) {
									$txt = $txtssm;
									$whattype = "ssm";
								} elsif (defined($txt)) {
								}
							}

							if (not defined($txt)) {
								print " -- ";
							} else {
#								print "    ";
								printf("%-3d ",$txt);
							}
						} else {
							if (not defined($txt) and not defined($txtssm)) {
								print " -- ";
							}
						}
					} elsif ($a eq $b) {
						print "    ";
					} else {
						print " -- ";
					}
				}
			}
			print "\n";
		}
	}

}
