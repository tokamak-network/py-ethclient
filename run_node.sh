#!/bin/bash

source .venv/bin/activate && sequencer --prefunded-private-key ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 --block-time 12 --db-path sqlite.db
