#!/bin/bash

jq -r "[.hints|to_entries|.[].value.[]|pick(.code)]|unique|sort_by(.code)" build/os_latest.json