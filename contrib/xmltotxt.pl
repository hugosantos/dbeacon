#A little perl script to generate the adjacency matrix given
#hugo santos XML dbeacon input file
#usage : perl xmltohtxt.pl dump.xml
#Hoerdt Mickaël 15/03/05


use Graph::Directed;
use XML::Parser;
use strict;

my $current_beacon;
my %adjacency_matrix;
my $parser;
my $g;

$g = new Graph::Directed;
# initialize parser and read the file
$parser = new XML::Parser( Style => 'Tree' );
$parser->setHandlers(Start => \&start_handler);
my $tree = $parser->parsefile( shift @ARGV );

my $am = Graph::AdjacencyMatrix->new($g);
my @V = $g->vertices();

	printf("ASM/ttl        |");
my $c;
my $i=0;
foreach $c (@V) {

	printf("%-2d|",$i);
	$i++;
}
print "\n";
$i=0;
foreach $a (@V) {
	printf("|%-2d.%-10s |",$i,substr($a,0,10));
	$i++;
	foreach $b (@V) {
#		if($am->is_adjacent($a,$b)) {
		if($g->has_edge($a,$b)) {
		my $ttl=$g->get_edge_attribute($a,$b,"ttl");
		printf("$ttl |");
#		printf("X |");
		} else {
		print("  |");
		}
	}
	print "\n";
}

sub start_handler
{
	my ($p, $tag, %atts) = @_;
	my $name;
	my $value;

	if($tag eq "beacon") {
		while(($name,$value) = each %atts) {
			if($name eq "name") {
				$current_beacon=$value;
				$g = $g->add_vertex($current_beacon);
			}
		}
	}

	if($tag eq "source") {
		my $ttl=-1;
		my $u=$current_beacon;
		my $v;
		while(($name,$value) = each %atts) {
			if($name eq "name") {
				$v=$value;
				$g = $g->add_vertex($v);
				$g = $g->add_edge($current_beacon,$v);
			}
			if($name eq "ttl") {
				$ttl=$value;
			}
		}
		$g->set_edge_attribute($u, $v,"ttl",$ttl)
	}
}
