**Build scripts**

These build scripts are used to allow easy cross compilation. They download a tarred copy of all the OpenWRT toolchains we use from updates.altheamesh.com if one is not already found locally. The main script you should interact with is `openwrt-upload.sh` you simply need to edit the target arch and then the Rust target before running it. 

**Device to arch mappings**

MIPS
* WD MyNet n600
* WD MyNet n750
* Archer C7 (all variants)
* Unifi AP AC lite (all variants)

MIPSEL
* EdgerouterX
* D-link dir860l

MVEBU
* Turris Omnia
* espressobin

IPQ40xx
* Zyxel Armor V2
* Gil Inet B1300

OCTEON
* Edgerouter Lite


**x86 Linux static builds**

The script `linux-build-static.sh` uses the musl Rust docker container to make portalbe x86 binaries that are totally statically linked, these sometimes have issues with opt parameters, so I suggest building them with no opt and debug or on Stable rust. 

