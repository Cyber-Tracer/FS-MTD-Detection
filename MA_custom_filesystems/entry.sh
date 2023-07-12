#!/bin/bash

mkdir /home/john/FTP
umount /home/john/FTP
rm logs/logfile{0..9}*
bash -c 'cd /detection/MA_custom_filesystems/rename_fs/; ./rename_fs-linux &> /detection/MA_custom_filesystems/fs.log' &

bash -c 'cd /detection/MA_custom_filesystems/python_classifier/; python3 detection_system.py'

