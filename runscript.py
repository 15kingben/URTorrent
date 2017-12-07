import os
import sys
import time

N = 4
if len(sys.argv) > 1:
    N = int(sys.argv[1])

for i in range(1, N+1):
    os.system("mkdir u" + str(i))

for i in range(1, N+1):
    os.system("cp -r bcode u" + str(i) + "/")


os.system("cp treatmelikeapirate.mp3 u1")

for i in range(1, N+1):
    os.system("cp treatmelikeapirate.mp3.torrent u" + str(i))

for i in range(1, N+1):
    os.system("cp urtorrent.py u" + str(i) + "/")

os.system("python3 BitTornado/bttrack.py --port 6969 --dfile poop.txt &")

for i in range(1, N+1):
    os.chdir("u" + str(i))
    os.system("python3 urtorrent.py 700" + str(i) + " treatmelikeapirate.mp3.torrent 0 &")
    print("u" + str(i) + " started")
    time.sleep(3)
    os.chdir("..")

while(True):
    time.sleep(1)
