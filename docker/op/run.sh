#!/usr/bin/env bash

trap 'kill ${!}; term_handler' SIGHUP SIGINT SIGQUIT SIGTERM

pid=0

term_handler() {
  echo "term_handler"
  service ntp stop
  if [ $pid -ne 0 ]; then
    kill -SIGTERM "$pid"
    wait "$pid"
  fi
  exit 143; # 128 + 15 -- SIGTERM
}

service ntp start
service apache2 start

echo -n "Starting node example ... "
node example &
pid="$!"
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
