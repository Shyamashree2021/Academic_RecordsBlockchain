#!/bin/bash

#
# Copyright IBM Corp All Rights Reserved
#
# SPDX-License-Identifier: Apache-2.0
#

# This is a collection of bash functions used by different scripts

# Color Environment Variables
export NC='\033[0m'
export GREEN='\033[0;32m'
export RED='\033[0;31m'
export YELLOW='\033[0;33m'
export BLUE='\033[0;34m'

# display variables as green text
function infoln() {
  echo -e "${GREEN}${1}${NC}"
}

# display variables as red text
function errorln() {
  echo -e "${RED}${1}${NC}"
}

# display variables as yellow text
function warnln() {
  echo -e "${YELLOW}${1}${NC}"
}

# display variables as green text
function successln() {
  echo -e "${GREEN}${1}${NC}"
}

# display variables as blue text
function trueln() {
  echo -e "${BLUE}${1}${NC}"
}

# print the header of the script
function printHeader() {
  echo -e "${BLUE}====================================================${NC}"
  echo -e "${BLUE}${1}${NC}"
  echo -e "${BLUE}====================================================${NC}"
}
