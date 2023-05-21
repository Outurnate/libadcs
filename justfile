docserver:
  cargo doc
  killall webfsd || true
  webfsd -r target/doc

deploy:
  cd adcs-submit && cargo build
  sshpass -p "Password1" scp target/debug/adcs-submit root@192.168.100.250:/

