![A lock with a mint leaf](https://ipv.sx/mint/mint.svg)

mint - A Minimal TLS 1.3 stack
==============================

[![Build Status](https://circleci.com/gh/bifurcation/mint.svg)](https://circleci.com/gh/bifurcation/mint)

This project is primarily a learning effort for me to understand the [TLS
1.3](http://tlswg.github.io/tls13-spec/) protocol.  The goal is to arrive at a
pretty complete implementation of TLS 1.3, with minimal, elegant code that
demonstrates how things work.  Testing is a priority to ensure correctness, but
otherwise, the quality of the software engineering might not be at a level where
it makes sense to integrate this with other libraries.  Backward compatibility
is not an objective.

We borrow liberally from the [Go TLS
library](https://golang.org/pkg/crypto/tls/), especially where TLS 1.3 aligns
with earlier TLS versions.  However, unnecessary parts will be ruthlessly cut
off.

## Quickstart

Installation is the same as for any other Go package:

```
go get github.com/bifurcation/mint
```

The API is pretty much the same as for the TLS module, with `Dial` and `Listen`
methods wrapping the underlying socket APIs.

```
conn, err := mint.Dial("tcp", "localhost:4430", &mint.Config{...})
...
listener, err := mint.Listen("tcp", "localhost:4430", &mint.Config{...})
```

Documentation is available on
[godoc.org](https://godoc.org/github.com/bifurcation/mint)


## Interoperability testing

The `mint-client` and `mint-server` executables are included to make it easy to
do basic interoperability tests with other TLS 1.3 implementations.  The steps
for testing against NSS are as follows.

```
# Install mint
go get github.com/bifurcation/mint

# Environment for NSS
NSS_ROOT=<whereever you want to put NSS>
export USE_64=1
export NSS_ENABLE_TLS_1_3=1
export DYLD_LIBRARY_PATH=dist/$PLATFORM/lib
export LD_LIBRARY_PATH=dist/$PLATFORM/lib
export HOST=localhost
# You can just copy this once NSS builds
export PLATFORM=$(uname -s)$(uname -r | cut -f 1-2 -d . -)_$(uname -m)_${CC:-cc}_glibc_PTH_64_$([ -n "$BUILD_OPT" ] && echo OPT || echo DBG).OBJ

# Build NSS
hg clone https://hg.mozilla.org/projects/nss
hg clone https://hg.mozilla.org/projects/nspr
cd nss
make nss_build_all

# Run NSS tests (this creates data for the server to use)
cd tests/ssl_gtests
./ssl_gtests.sh

# Test with client=mint server=NSS
cd $NSS_ROOT
dist/$PLATFORM/bin/selfserv -d tests_results/security/$HOST/ssl_gtests/ -n rsa -p 4430
# ...
go run $GOPATH/src/github.com/bifurcation/mint/bin/mint-client/main.go

# Test with client=NSS server=mint
go run $GOPATH/src/github.com/bifurcation/mint/bin/mint-server/main.go
# ...
cd $NSS_ROOT
dist/$PLATFORM/bin/tstclnt -d tests_results/security/$HOST/ssl_gtests/ -V tls1.3:tls1.3 -h 127.0.0.1 -p 4430 -o -O
```

