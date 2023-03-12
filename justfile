docserver:
  killall webfsd || true
  cargo doc
  webfsd -r target/doc
