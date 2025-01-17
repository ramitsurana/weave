#!/bin/bash

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SLOW=${SLOW-}
GO_TEST_ARGS="-tags netgo -cpu 4"
if [ -n "$SLOW" -o "$1" = "-slow" ]; then
    GO_TEST_ARGS="$GO_TEST_ARGS -race -covermode=atomic"

    if [ -n "$COVERDIR" ] ; then
        coverdir="$COVERDIR"
    else
        coverdir=$(mktemp -d coverage.XXXXXXXXXX)
    fi

    mkdir -p $coverdir
fi

fail=0

TESTDIRS=$(find . -type f -name '*_test.go' | xargs -n1 dirname | grep -v prog | sort -u)

# If running on circle, use the scheduler to work out what tests to run on what shard
if [ -n "$CIRCLECI" -a -z "$NO_SCHEDULER" ]; then
    TESTDIRS=$(echo $TESTDIRS | "$DIR/sched" sched units-$CIRCLE_BUILD_NUM $CIRCLE_NODE_TOTAL $CIRCLE_NODE_INDEX)
    echo $TESTDIRS
fi

for dir in $TESTDIRS; do

    GO_TEST_ARGS_RUN="$GO_TEST_ARGS"
    if [ -n "$SLOW" ]; then
        go get -t -tags netgo $dir
        output=$(mktemp $coverdir/unit.XXXXXXXXXX)
        GO_TEST_ARGS_RUN="$GO_TEST_ARGS -coverprofile=$output"
    fi

    START=$(date +%s)
    if ! go test $GO_TEST_ARGS_RUN $dir ; then
        fail=1
    fi
    RUNTIME=$(( $(date +%s) - $START ))

    # Report test runtime when running on circle, to help scheduler
    if [ -n "$CIRCLECI" -a -z "$NO_SCHEDULER" ]; then
        "$DIR/sched" time $dir $RUNTIME
    fi
done

if [ -n "$SLOW" -a -z "$COVERDIR" ] ; then
    $DIR/../testing/cover/cover $coverdir/* >profile.cov
    rm -rf $coverdir
    go tool cover -html=profile.cov -o=coverage.html
    go tool cover -func=profile.cov | tail -n1
fi

exit $fail
