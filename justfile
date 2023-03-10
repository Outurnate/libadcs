docserver:
  killall webfsd
  cargo doc
  webfsd -r target/doc
