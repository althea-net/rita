FROM ubuntu:trusty
RUN sudo apt-get -qq update
RUN sudo apt-get install -y curl git wget tar build-essential python-pip libssl-dev libffi-dev python-dev subversion libncurses5-dev zlib1g-dev gawk gcc-multilib flex git-core gettext unzip systemtap-sdt-dev
RUN useradd -s /bin/bash build
RUN mkdir /home/build; chown -R build /home/build
RUN sudo pip install --upgrade pip; pip install --upgrade setuptools ; sudo pip install --upgrade ansible
USER build
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
RUN /home/build/.cargo/bin/rustup default nightly
RUN cd /home/build; git clone https://github.com/althea-mesh/althea-firmware
RUN cd /home/build/althea-firmware; ansible-playbook -e @profiles/devices/n600.yml -e @profiles/management/althea-dev.yml firmware-build.yml; exit 0
RUN cd home/build/althea-firmware/build; tar -czf staging-mips.tar.gz staging_dir/ 
