#!/usr/bin/python3

# Input: facts.pl
# Output: cvemetric.csv storing the CVEID, probability, impact

import sys
import re


path_in1 = sys.argv[1] # path to config.pl
path_out = path_in1.replace('facts.pl', 'cvemetric.csv')

fin1 = open(path_in1, 'r')
fout = open(path_out, 'w')

# process config.pl to get CVEID and CORRECT initial probability and impact score
# vul_properties = {}
for line in fin1.readlines():
    if 'vulPropertyV2' in line:
        temp = line.split(',')
        cveid = re.findall("'(.*?)'", temp[0])[0] # find CVEID
        prob = float(re.findall("(\d+(?:\.\d+)?)", temp[-2])[0]) # find probability
        impact = float(re.findall("(\d+(?:\.\d+)?)", temp[-1])[0]) # find impact

        # vul_properties[cveid] = [prob, impact]
        fout.write(','.join((cveid, str(prob), str(impact))))
        fout.write('\n')

fin1.close()
fout.close()
