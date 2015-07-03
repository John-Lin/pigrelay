import os

os.system("wget --no-check-certificate https://github.com/John-Lin/pigrelay/archive/master.zip")
os.system("unzip master.zip")
os.system("rm -rf master.zip")

os.system("mv pigrelay-master pigrelay-new")
