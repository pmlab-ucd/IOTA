#!/bin/bash

## This Bash script automates the generation of attack graph given the facts.pl, rules.pl, and main.pl

# run xsb to generate trace_output.P
xsb 2>xsb_log.txt 1>&2 <<EOF
[main].
EOF

# set environment variables
PROJ_ROOT=/home/zheng/iota_ultimate
MULVAL_ROOT=/opt/mulval

# run trimming script to process trace_output.P
$PROJ_ROOT/python/util/trim_trace.py trace_output.P
$MULVAL_ROOT/bin/attack_graph -l trace_output_trim.P > result.txt

# attack graph generation pipeline
grep -E "AND|OR|LEAF" result.txt > VERTICES.CSV
grep -Ev "AND|OR|LEAF" result.txt > ARCS.CSV

$PROJ_ROOT/python/util/fix_vert_prob.py trace_output.P VERTICES.CSV
$PROJ_ROOT/python/util/config2cve_metric.py facts.pl

# compute the probability for each node of the attack graph, and output number of nodes / edges, depth
var=$(java -cp $PROJ_ROOT/bin/metrics/ Graph `pwd`"/")

# render AttackGraph.pdf
$MULVAL_ROOT/utils/render.sh > /dev/null
