# Documentation extractors

The release builder runs language-native extractors against installed artifacts,
then `cargo xtask docs-bundle` normalizes their bounded output. Extractors emit
facts only: symbols, signatures, source documentation, stable operation joins,
and package provenance. Website prose does not enter this directory.
