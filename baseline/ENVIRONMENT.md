# Baseline environment  (captured 2026-08-26T17:50:53Z)

git_branch      : fix-linux-blackbox-script
git_sha         : f04f17dbb35605d62a74ee7ac334833d880d7df4
afl_fuzz        : afl-fuzz++4.09c
clang           : Ubuntu clang version 18.1.3 (1ubuntu1)
kernel          : Linux 7.0.0-28-generic
cpu             : Intel(R) Core(TM) Ultra 7 155U
cpu_cores       : 14
mem_total       : 15Gi
disk_model      : BC901 NVMe SK hynix 512GB
tmpfs_dev_shm   : 7.6G total, 7.4G free
python          : Python 3.12.3

# Pre-fix measured write cost (from the 1s smoke, cache-masked):
execs_per_sec   : 90.13
corpus_apk_bytes: 12426276   (F-Droid.apk)
=> naive write  : ~1.12 GB/s  ->  ~580 TB over a 144h campaign
