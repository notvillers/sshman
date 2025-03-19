#!/bin/bash
script_dir=$(dirname "$0")
cd $script_dir
source .venv/bin/activate
python ssh_man.py "$@"
deactivate