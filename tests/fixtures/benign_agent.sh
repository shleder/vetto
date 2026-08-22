#!/bin/sh
# Benign agent: works inside its project, touches nothing outside.
echo "benign-start"
echo "created-by-agent" > ./vetto-benign.txt
cat ./vetto-benign.txt
# Give the /proc visibility poller a chance to observe us.
sleep 1.5
echo "benign-done"
