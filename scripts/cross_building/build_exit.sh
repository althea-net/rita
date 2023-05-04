# #!/bin/bash

cd cross-builders/exit
docker build -t cross-with-clang-ssl .
cp Cross.toml ../..
cd ../..
cross build --release --target x86_64-unknown-linux-gnu -p rita_bin --bin rita_exit
rm Cross.toml 
