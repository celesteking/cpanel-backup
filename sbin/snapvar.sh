#!/bin/bash

export HOME=$( getent passwd "root" | cut -d: -f6 )
snap_mnt=/mnt/var
mysql_dir=/var/lib/mysql
snap_size=5g

set -e

src=$(findmnt -n --output=source -T ${mysql_dir})
if [ "$2" = "fail_non_var" ]; then
        lv=$(lvs  --noheadings -o lv_name ${src} | xargs)
        if [ "$lv" != "var" ]; then
                echo "error: $src: $lv is not 'var'!"
                exit 1
        fi
fi

function engage() {
	(
		echo "FLUSH TABLES WITH READ LOCK;"
		echo "\\! sync -f $mysql_dir && lvcreate -q -s -n ${src}.snap -L $snap_size $src"
		echo "UNLOCK TABLES;"
	) | mysql -B
	
	mkdir -p ${snap_mnt}
	mountpoint -q ${snap_mnt} && exit 1
	mount -o ro $src.snap ${snap_mnt}
}

function release() {
	umount ${snap_mnt} || :
	lvremove -qy ${src}.snap
}

case $1 in
	mount)
		engage
		;;
	release)
		release
		;;
	*)
		echo "./$0 mount|release"
		;;
esac
