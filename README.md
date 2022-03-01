# IOTA
This is the source code of the paper *Iota: A Framework for Analyzing System-Level Security of IoTs* (https://arxiv.org/pdf/2202.02506.pdf)

Suppose the project root is `PROJ_ROOT`

## Set up MySQL server
`PROJ_ROOT/java/src/main/java`

Specify the local MySQL server's username, password, and the path to the NVD-CVE JSON files

## Set up Stanford CoreNLP server
`$ java -mx4g -cp "*" edu.stanford.nlp.pipeline.StanfordCoreNLPServer -preload tokenize,ssplit,pos,lemma,ner,parse,deparse -status_port 9000 -port 9000 -timeout 15000 &`

## Install XSB

## Install MulVAL

## Vulnerability Scanner
`PROJ_ROOT/python/vul_scanner.py`

## App Semantic Extractor
In `PROJ_ROOT/python/app_logic_extractor.py`, set `PATH_TO_PRE_TRAINED_WORD2VEC_MODEL`

## Vulnerability Analyzer
`PROJ_ROOT/python/vul_analyzer.py`

## Translator
`PROJ_ROOT/python/translator.py`

## Graph Analyzer
`PROJ_ROOT/python/graph_analyzer.py`
