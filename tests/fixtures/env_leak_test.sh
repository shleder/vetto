#!/bin/sh
set -eu

env | grep -iE '(^|_)(token|key|secret)(_|=|$)' || true
