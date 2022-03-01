#!/usr/bin/python3

# Input: trace_output.P, VERTICES.CSV
# Output: VERTICES.CSV with fixed original probabilities

import sys
import csv
import os

path_in1 = sys.argv[1] # path to trace_output.P
path_in2 = sys.argv[2] # path to VERTICES.CSV
path_out = path_in2.replace('.CSV', '_fix.CSV')

fin1 = open(path_in1, 'r')
fin2 = open(path_in2, 'r')
fout = open(path_out, 'a')

# process trace_output.P to get rule description and CORRECT probability
res1 = {}
for line in fin1.readlines():
    if 'possible_duplicate_trace_step' in line:
        tokens = line.split(',')
        tmp_desc = tokens[1][11:-1]
        tmp_prob = float(tokens[2])

        if tmp_desc not in res1:
            res1[tmp_desc] = tmp_prob

# process VERTICES.CSV to get rule description and WRONG probability
reader = csv.reader(fin2, delimiter=',')
writer = csv.writer(fout, delimiter=',', quoting=csv.QUOTE_NONNUMERIC)
for row in reader:
    row[0] = int(row[0])
    if row[2] == 'AND':
        for desc in res1:
            if desc in row[1]:
                row[3] = res1[desc]
    row[3] = float(row[3])
    writer.writerow(row)

fout.close()
fin1.close()
fin2.close()

os.remove(path_in2)
os.rename(path_out, path_out.replace('_fix.CSV', '.CSV'))
