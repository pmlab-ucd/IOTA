#!/usr/bin/python3

# Input: trace_output.P
# Output: trace_output_trim.P

import sys

path_in = sys.argv[1] # path to trace_output.P
path_out = path_in.replace('.P', '_trim.P')

fin = open(path_in, 'r')
fout = open(path_out, 'w')

for line in fin.readlines():
    if 'possible_duplicate_trace_step' not in line:
        fout.write(line)
    else:
        tokens = line.split(',')
        tokens[3] = ')'
        fout.write(','.join(tokens[:3]) + ','.join(tokens[3:]))

fout.close()
fin.close()
