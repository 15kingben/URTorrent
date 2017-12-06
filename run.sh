mkdir u1
mkdir u2
mkdir u3
mkdir u4

cp -r bcode u1/
cp -r bcode u2/
cp -r bcode u3/
cp -r bcode u4/

cp treatmelikeapirate.mp3 u1
cp treatmelikeapirate.mp3.torrent u1
cp treatmelikeapirate.mp3.torrent u2
cp treatmelikeapirate.mp3.torrent u3
cp treatmelikeapirate.mp3.torrent u4

cp urtorrent.py u1/
cp urtorrent.py u2/
cp urtorrent.py u3/
cp urtorrent.py u4/

python3 BitTornado/bttrack.py --port 6969 --dfile poop.txt &

cd u1
python3 urtorrent.py 7001 treatmelikeapirate.mp3.torrent &
echo u1 started
sleep 1
cd ../u2
python3 urtorrent.py 7002 treatmelikeapirate.mp3.torrent &
echo u2 started
cd ../u3
sleep 1
python3 urtorrent.py 7003 treatmelikeapirate.mp3.torrent &
echo u3 started
cd ../u4
sleep 1
python3 urtorrent.py 7004 treatmelikeapirate.mp3.torrent &
echo u4 started
