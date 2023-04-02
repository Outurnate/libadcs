docserver:
  cargo doc
  killall webfsd || true
  webfsd -r target/doc

deploy:
  cd adcs-submit && cargo build --release
  sshpass -p "Password1" scp target/release/adcs-submit root@192.168.100.250:/
