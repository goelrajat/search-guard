#!/bin/bash
/home/data/elasticsearch-6.2.4/plugins/search-guard-6/tools/sgadmin.sh -h 192.168.154.190 -cd /home/data/elasticsearch-6.2.4/plugins/search-guard-6/sgconfig -icl -key /home/data/elasticsearch-6.2.4/config/kirk-key.pem -cert /home/data/elasticsearch-6.2.4/config/kirk.pem -cacert /home/data/elasticsearch-6.2.4/config/root-ca.pem -nhnv
