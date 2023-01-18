#!/bin/sh

# From AzureWatson crash listener

g++ -flto --std=c++17 -I. -ggdb0 -O2 -static -o ../uh-dump *.cpp
strip ../uh-dump
