#!/bin/bash

echo "Installing dependencies..."
pip install -r requirements.txt

echo "Starting miner..."
python3 fast_miner.py
