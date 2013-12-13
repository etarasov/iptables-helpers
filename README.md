# iptables-helper

# How to Test

```
cabal configure --enable-tests
cabal build
cabal test --test-option=--maximum-generated-tests=100
```

or

```
cabal configure
cabal build
dist/build/iptables-helpers-test/iptables-helpers-test --test
```
