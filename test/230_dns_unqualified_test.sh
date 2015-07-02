#! /bin/bash

. ./config.sh

C1=10.2.0.78
C2=10.2.0.34
C3=10.2.0.57
C4=10.2.0.99
DOMAIN=weave.local
NAME=seeone.$DOMAIN

start_suite "Resolve unqualified names"

launch_dns_on $HOST1 10.2.254.1/24

start_container          $HOST1 $C1/24 --name=c1 -h $NAME
start_container_with_dns $HOST1 $C2/24 --name=c2 -h seetwo.$DOMAIN
start_container_with_dns $HOST1 $C3/24 --name=c3 --dns-search=$DOMAIN
container=$(start_container_with_dns $HOST1 $C4/24)

check() {
  assert "exec_on $HOST1 $1 getent hosts seeone | tr -s ' '" "$C1 $NAME"
}

check c2
check c3
check "$container"

# check that unqualified names are automatically qualified when looking up
weave_on $HOST1 dns-add $C2 c2 -h name1.$DOMAIN
assert_dns_a_record $HOST1 c2 name1 $C2 name1.$DOMAIN

end_suite
