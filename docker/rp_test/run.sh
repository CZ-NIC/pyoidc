#!/usr/bin/env bash

trap 'kill ${!}; term_handler' SIGHUP SIGINT SIGQUIT SIGTERM

term_handler() {
  echo "term_handler"
  killall python3
  exit 143; # 128 + 15 -- SIGTERM
}

echo -n "Starting config_server.py ... "
python3 server.py -f flows -p 8080 -k -t conf &
if [ $? -eq 0 ] ; then
  echo "OK"
else
  echo "ERROR"
  exit -1
fi

while true
do
  tail -f /dev/null & wait ${!}
done

echo "exited $0"
