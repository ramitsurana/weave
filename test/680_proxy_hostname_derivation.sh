#! /bin/bash

. ./config.sh

C1=10.2.0.78
C2=10.2.0.34
C3=10.2.0.57
CNAME1=qiuds71y827hdi-seeone-1io9qd9i0wd
NAME1=seeone.weave.local
CNAME2=124DJKSNK812-seetwo-128hbaJ881
NAME2=seetwo.weave.local
CNAME3=doesnotmatchpattern
NAME3=doesnotmatchpattern.weave.local

start_container() {
  proxy docker_on $HOST1 run "$@" -dt $DNS_IMAGE /bin/sh
}

start_suite "Hostname derivation through container name substitutions"

weave_on $HOST1 launch-dns 10.2.254.1/24
weave_on $HOST1 launch-proxy --hostname '/[^-]+-(?P<appname>[^-]*)-[^-]+/$appname/'

start_container -e WEAVE_CIDR=$C1/24 --name=$CNAME1
start_container -e WEAVE_CIDR=$C2/24 --name=$CNAME2
start_container -e WEAVE_CIDR=$C3/24 --name=$CNAME3

check() {
  assert "proxy exec_on $HOST1 $1 getent hosts $2 | tr -s ' '" "$3 $2"
}

check $CNAME1 $NAME2 $C2
check $CNAME2 $NAME3 $C3
check $CNAME3 $NAME1 $C1

end_suite
