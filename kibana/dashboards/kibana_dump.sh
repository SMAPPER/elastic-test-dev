#!/bin/bash
sudo apt-get install python-pip
sudo pip install elasticsearch
sudo python ./kibana_dump.py --url http://localhost:9200
