# history.pm - build and read database file name and path
# required by history.pl and arch.pl

use strict;

sub build_host {
	my ($name,$addr) = @_;

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

				my ($name,$asmorssm) = get_name_from_host($dst);

                                push (@res, [$name." ($asmorssm)", $dst, "$start$dst", $final, $name, $asmorssm eq "ssm"]);
                        } else {
                                $dst =~ s/^(.+)\-.+$/$1/;
                                push (@res, [$dst, $dircontent, "$start$dircontent", $final]);
                        }
                }
        }

        close (DIR);

        return @res;
}

sub get_dstbeacons {
	my ($historydir, $url) = @_;
        return get_beacons($historydir, 0, "$url?dst=");
}

sub get_srcbeacons {
        my ($historydir, $url, $dst) = @_;
        return get_beacons("$historydir/$dst", 1, "$url?dst=$dst&src=");
}

sub get_name_from_host {
	my ($host) = @_;

	if ($host =~ /^(.+)\-.+\.(.+)$/)
	{
		return ($1,$2);
	}
	elsif ($host =~ /^(.+)\-.+$/)
	{
		return ($1);
	}
	return 0;
}

1;
