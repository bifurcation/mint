mint - A Minimal TLS 1.3 stack
==============================

This project is primarily a learning effort for me to understand the [TLS
1.3](http://tlswg.github.io/tls13-spec/) protocol.  The goal is to arrive at a
pretty complete implementation of TLS 1.3, with minimal, elegant code that
demonstrates how things work.  Testing is a priority to ensure correctness, but
otherwise, the quality of the software engineering might not be at a level where
it makes sense to integrate this with other libraries.  Backward compatibility
is not an objective.

We will borrow liberally from the [Go TLS
library](https://golang.org/pkg/crypto/tls/), especially where TLS 1.3 aligns
with earlier TLS versions.  However, unnecessary parts will be ruthlessly cut
off.

## Quickstart

```
go get github.com/bifurcation/mint
# TODO: API examples
```


