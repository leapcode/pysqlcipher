#!/bin/zsh
# BATCH STRESS TEST FOR IMAP ----------------------
# http://imgs.xkcd.com/comics/science.jpg
#
# Run imaptest against a LEAP IMAP server
# for a fixed period of time, and collect output.
#
# Author: Kali Kaneko
# Date: 2014 01 26
#
# To run, you need to have `imaptest` in your path.
# See:
# http://www.imapwiki.org/ImapTest/Installation
#
# For the tests, I'm using a 10MB file sample that
# can be downloaded from:
# http://www.dovecot.org/tmp/dovecot-crlf
#
# Want to contribute to benchmarking?
#
# 1. Create a pristine account in a bitmask provider.
#
# 2. Launch your bitmask client, with different flags
#    if you desire.
#
#    For example to try the nosync flag in sqlite:
#
#    LEAP_SQLITE_NOSYNC=1 bitmask --debug -N --offline -l /tmp/leap.log
#
# 3. Run at several points in time (ie: just after
#    launching the bitmask client. one minute after,
#    ten minutes after)
#
#    mkdir data
#    cd data
#    ../leap_tests_imap.zsh | tee sqlite_nosync_run2.log  
#
# 4. Submit your results to: kali at leap dot se
#    together with the logs of the bitmask run.
#
# Please provide also details about your system, and
# the type of hard disk setup you are running against.
#

# ------------------------------------------------
# Edit these variables if you are too lazy to pass
# the user and mbox as parameters. Like me.

USER="test_f14@dev.bitmask.net"
MBOX="~/leap/imaptest/data/dovecot-crlf"

HOST="localhost"
PORT="1984"

# in case you have it aliased
GREP="/bin/grep"
IMAPTEST="imaptest"

# -----------------------------------------------
#
# These should be kept constant across benchmarking
# runs across different machines, for comparability.

DURATION=200
NUM_MSG=200


# TODO add another function, and a cli flag, to be able
# to take several aggretates spaced in time, along a period
# of several minutes.

imaptest_cmd() {
  stdbuf -o0 ${IMAPTEST} user=${USER} pass=1234 host=${HOST} \
	  port=${PORT} mbox=${MBOX} clients=1 msgs=${NUM_MSG} \
	  no_pipelining 2>/dev/null
}

stress_imap() 	{
  mkfifo imap_pipe
  cat imap_pipe | tee output &
  imaptest_cmd >> imap_pipe
}

wait_and_kill() {
  while : 
  do
    sleep $DURATION
    pkill -2 imaptest
    rm imap_pipe
    break
  done
}

print_results() {
	sleep 1
	echo
	echo
	echo "AGGREGATED RESULTS"
	echo "----------------------"
	echo "\tavg\tstdev"
	$GREP "avg" ./output | sed -e 's/^ *//g' -e 's/ *$//g' | \
	gawk '
function avg(data, count) {
    sum=0;
    for( x=0; x <= count-1; x++) {
        sum += data[x];
    }
    return sum/count;
}
function std_dev(data, count) {
    sum=0;
    for( x=0; x <= count-1; x++) {
        sum += data[x];
    }
    average = sum/count;

    sumsq=0;
    for( x=0; x <= count-1; x++) {
        sumsq += (data[x] - average)^2;
    }
    return sqrt(sumsq/count);
}
BEGIN {
  cnt = 0
} END {

printf("LOGI:\t%04.2lf\t%04.2f\n", avg(array[1], NR), std_dev(array[1], NR));
printf("LIST:\t%04.2lf\t%04.2f\n", avg(array[2], NR), std_dev(array[2], NR));
printf("STAT:\t%04.2lf\t%04.2f\n", avg(array[3], NR), std_dev(array[3], NR));
printf("SELE:\t%04.2lf\t%04.2f\n", avg(array[4], NR), std_dev(array[4], NR));
printf("FETC:\t%04.2lf\t%04.2f\n", avg(array[5], NR), std_dev(array[5], NR));
printf("FET2:\t%04.2lf\t%04.2f\n", avg(array[6], NR), std_dev(array[6], NR));
printf("STOR:\t%04.2lf\t%04.2f\n", avg(array[7], NR), std_dev(array[7], NR));
printf("DELE:\t%04.2lf\t%04.2f\n", avg(array[8], NR), std_dev(array[8], NR));
printf("EXPU:\t%04.2lf\t%04.2f\n", avg(array[9], NR), std_dev(array[9], NR));
printf("APPE:\t%04.2lf\t%04.2f\n", avg(array[10], NR), std_dev(array[10], NR));
printf("LOGO:\t%04.2lf\t%04.2f\n", avg(array[11], NR), std_dev(array[11], NR));

print ""
print "TOT samples", NR;
}
{
  it = cnt++;
  array[1][it] = $1;
  array[2][it] = $2;
  array[3][it] = $3;
  array[4][it] = $4;
  array[5][it] = $5;
  array[6][it] = $6;
  array[7][it] = $7;
  array[8][it] = $8;
  array[9][it] = $9;
  array[10][it] = $10;
  array[11][it] = $11;
}'
}


{ test $1 = "--help" } && {
 echo "Usage: $0 [user@provider] [/path/to/sample.mbox]"
 exit 0
}

# If the first parameter is passed, take it as the user
{ test $1 } && {
 USER=$1
}

# If the second parameter is passed, take it as the mbox
{ test $2 } && {
 MBOX=$2
}

echo "[+] LEAP IMAP TESTS"
echo "[+] Running imaptest for $DURATION seconds with $NUM_MSG messages"
wait_and_kill &
stress_imap
print_results
