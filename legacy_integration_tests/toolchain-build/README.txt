This is a docker script to build the toolchain tar for the build-cross.sh. 

Use docker build .
then docker run -it <final image id> /bin/bash 
then docker cp <running container id from docker ps">:/home/build/althea-firmware/build/staging-mips.tar.gz .

Finally 
scp the resulting tar up to the webserver so it's accessible on updates.altheamesh.com/staging-mips.tar.gz
