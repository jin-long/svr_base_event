#!/bin/sh

:<<!
    start 10000 net_cli test net_svr
!

count=10000
i=1


while [ $i -le $count ]
do
    /home/xsw/multi_cli_net/project/net_cli $i &
    i=`expr $i + 1`;
    continue
done

