#!/usr/bin/python3

# Imports
import os, sys
from optparse import OptionParser

import datetime
from datetime import *
import dateutil.parser
import re

########################################################################
# Print an error message and exit.
def error(errorMessage, exitValue=1):
    print("\nError:  " + errorMessage)
    progName = os.path.basename(sys.argv[0]) # could also use __file__
    print("\n(Use '" + progName + " -h' for help.)")
    sys.exit(exitValue)

# We expect to run as main:
if __name__ != "__main__":
    error("This script is expected to run in __main__ context.")

# Enforce minimum version.  
EXPECTED_VERSION=(3,6)
if sys.version_info < EXPECTED_VERSION:
    print("\nError: Must run on python:  " + str(EXPECTED_VERSION[0])+"."+str(EXPECTED_VERSION[1]) + " or greater.")
    print(  "  Detected python version:  " + str(sys.version_info))
    sys.exit(1)

# Parse the options and parameters.
# Note, the formatting is not preserved in -h.
usageText="""This script takes input from stdin and echoes it back if the filter
requirements are met.  (See Options.)

The datetime filters are all OR-ed together.  Ie., if ANY ISO-formatted datetime
field is found in the input line that matches the specified filters, the record
will pass through the filter.  Similarly, if NO datetime fields match the 
filter, it won't pass through.

The range filters (min and max) are lower and upper bounds of dates to allow
to pass through the filter, and are inclusive.

If no options are specified, no filtering is done.
"""
parser = OptionParser(
    usage='%prog [options]',
    description=usageText,
    epilog='Example (filter on just one day):  filter-iso-datetimes.py -m "2021-05-05T00:00:00Z" -x "2021-05-05T23:59:59.999999Z"',
    version='%prog v1.0')

# Options
parser.add_option(
    "-n", "--min-datetime", 
    dest="minDatetime",
    help="Specify the minimum datetime to pass through the filter (inclusive).", 
    metavar="MIN_DATE_TIME")
parser.add_option(
    "-x", "--max-datetime", 
    dest="maxDatetime",
    help="Specify the maximum datetime to pass through the filter (inclusive).", 
    metavar="MAX_DATE_TIME")
(options, args) = parser.parse_args()

#print("options = " + str(options))
#print("args = " + str(args))

# set range values properly
minDT = datetime.min.replace(tzinfo=timezone.utc)
if options.minDatetime:
    try: 
        minDT = dateutil.parser.isoparse(options.minDatetime)
    except Exception as e:
        error("unable to parse MIN_DATE_TIME: "+options.minDatetime)

maxDT = datetime.max.replace(tzinfo=timezone.utc)
if options.maxDatetime:
    try: 
        maxDT = dateutil.parser.isoparse(options.maxDatetime)
    except Exception as e:
        error("unable to parse MAX_DATE_TIME: "+options.maxDatetime)
    # if min and max both exist, make sure the min is not greater than max...
    if options.minDatetime and minDT > maxDT:
        error("MIN_DATE_TIME cannot be greater than MAX_DATE_TIME! min="+options.minDatetime+", max="+options.maxDatetime)


# Make sure stdin is not a tty (exits if input is empty)
if sys.stdin.isatty():
    error("stdin is a TTY.  Unable to proceed.")

for rawLine in sys.stdin:
    line = rawLine.rstrip('\n')

#    testStr = '{"A":0,"B":"2020-01-31T23:59:59.000001+09:09","C":"x","D":"2020-01-31T23:00:00.001Z","E":"2020-01-31T23:00","F":"1111-11-11"}'
#                           12345678901234567890123456789012
#                                   10        20        30

    # Note this regex is not exact.  We test it for real with the dateparser.
    # Also - this doesn't require double quotes around the value to detect an
    # iso date.  However, you may get false positives in the case of an incorrect
    # iso datetime like "2020-01-31T23:00:00.000001+00:000".  
    #allDatetimes = re.findall('" *(\d{4}-[\d\-T:\.+Z]{11,27}) *"', line)
    allDatetimes = re.findall('(\d{4}-[\d\-T:\.+Z]{11,27})', line)

    if (len(allDatetimes) > 0):
        letPass = False
        for dateStr in allDatetimes:
            try:
                dt = dateutil.parser.isoparse(dateStr)
                # if it is missing the offset, assume it's UTC:
                if dt.tzinfo == None:
                    dt = dt.replace(tzinfo=timezone.utc)

                if minDT <= dt and dt <= maxDT:
                    letPass = True
                    break
            except Exception as e:
                pass
                #error("couldn't parse datetime string (not in iso format): '"+dt+"'")

        if letPass:
            print(line)
        else:
            pass

sys.exit()

################ 
# testing script
##!/bin/bash
#
#set -ex
#
#F=filtertest-records.txt
#rm -fv $F
#echo '{"A":90,"B":"2020-01-31T23:00:00.0000001+00:00","C":"x","D":""}' >> $F
#echo '{"A":91,"B":"2020-01-31T23:00:00.000001+00:000","C":"x","D":""}' >> $F
#echo '{"A":0,"B":"2020-01-31T23:00:00.000001+00:00","C":"x","D":"2020-01-31T23:00:00.000002Z"}' >> $F
#echo '{"A":1,"B":"2020-01-31T23:00:00.000001Z","C":"x","D":"2020-01-31T23:00:00.000003Z"}' >> $F
#echo '{"A":92,"B":"2020-01-31T23:5","C":"x","D":""}' >> $F
#echo '{"A":2,"B":"2020-01-31T23:00","C":"x","D":"2020-01-31T23:00:00.000002Z"}' >> $F
#
##cat $F | ./filter-iso-datetimes.py -n "2020-01-31T23:00:00.000004+00:00"
#cat $F | ./filter-iso-datetimes.py -x "2020-01-31T23:00:00.000000+00:00"  

