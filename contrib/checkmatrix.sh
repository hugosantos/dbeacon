#!/bin/bash
#This little script can be run by cron to check 
#if the beacon matrix changed and send the new matrix by mail
#if this is the case

mail=blah@blah.blah
./xml2txt.pl > tmp.txt
if test -f tmpref.txt
then
	if ! cmp tmp.txt tmpref.txt > /dev/null
	then mail -s "Matrix changed" $mail < tmp.txt
	fi
	cp tmp.txt tmpref.txt
else
	cp tmp.txt tmpref.txt
fi
