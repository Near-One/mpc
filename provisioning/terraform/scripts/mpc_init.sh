#!/bin/bash
set -exo pipefail

# Takes disk alias and mount path as parameters
function disk_initial_setup {
  # Terraform attaches disks in random (well, not easily determinable) order
  # We first need to figure out device name
  disk_suffix=$1
  path=$2

  # Ensure that we can see attached disk
  echo "Looking for disk by id google*-$disk_suffix..."
  until L=$(readlink /dev/disk/by-id/google*-$disk_suffix)
  do
      sleep 1
  done
  disk=$(realpath /dev/disk/by-id/$L)

  echo Mounting $disk_suffix disk with name $disk to path $path

  # Ensure we can see the attached disk.
  echo "Looking for $disk..."
  until ls $disk
  do
      sleep 1
  done
  
  # Format the device, if necessary.
  until file -s $(realpath $disk) | cut -d , -f1 | grep ext4
  do
      mkfs.ext4 -m 0 -E lazy_itable_init=0,lazy_journal_init=0,discard $disk
  done
  
  # Ensure the disk is formatted.
  until file -s $(realpath $disk) | cut -d , -f1 | grep ext4
  do
      echo "Disk not formatted as ext4... exiting!"
      exit 1
  done
  fsck.ext4 -p $disk
  
  # Create a mount point.
  mkdir -p $path 
  # ... and mount.
  mount -o discard,defaults $disk $path

  # this will instantiate UUID variable with disk UUID value
  # $ blkid /dev/sdc | cut -d ' ' -f 2
  # UUID="2b2e50ed-03f9-4831-8922-58d90f5aaaaa"
  eval $(blkid $disk | cut -d ' ' -f 2)

  # Clearing disk from fstab  (if present)
  sed -i -e "\|$disk|d" -e "\|$UUID|d" /etc/fstab
  echo "UUID=$UUID $path ext4 discard,defaults,nofail 0 2" >> /etc/fstab
  
  resize2fs $disk
}

#If already have some of data dirs then initial setup was already done
if [ -d "$MPC_DIR/data"]; then
  echo "Data directory already exist, there is no need to initial setup, exiting..."
  docker rm watchtower; 
  docker run -d --name watchtower -v /var/run/docker.sock:/var/run/docker.sock containrrr/watchtower --debug --interval 30
  exit 0;
fi

MPC_DIR=/home/mpc/
disk_initial_setup 1 "$MPC_DIR"

mkdir -p $MPC_DIR/data

docker rm watchtower; 
docker run -d --name watchtower -v /var/run/docker.sock:/var/run/docker.sock containrrr/watchtower --debug --interval 30