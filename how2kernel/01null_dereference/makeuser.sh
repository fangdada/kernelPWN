insmod *.ko
mkdir -p /home/fanda
touch /etc/passwd
touch /etc/group
adduser fanda

sysctl -w vm.mmap_min_addr="0"
su fanda
