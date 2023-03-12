docserver:
  cargo doc
  killall webfsd || true
  webfsd -r target/doc
