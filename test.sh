#!/bin/bash
# free5gc
#python3 5g_aka.py -M 208 -N 93 -I 2089300007487 \
#    -K 5122250214c33e723a5dd523fc145fc0 \
#    -P c9e8763286b5b9ffbdf56e1297d0887b \
#    -R cbeed9825487941484dfc525d06daba3 \
#    -A 3805f711694680007350347df87246a9
#echo 'expect RES: 05ed041443b4e3ff7b8f9618d3915bc1'

# III n3iwf log
#python3 5g_aka.py -M 466 -N 66 -I 466666100000001 \
#    -K 000102030405060708090a0b0c0d0e0f \
#    -P cdc202d5123e20f62b6d676ac72cb318 \
#    -R 0610b1561ca7e79d68cbf9505fb41c6a \
#    -A 97a167ded889b6dfa92d985d77e5c088
#echo 'expect RES: 00eb44f4fdd77533ca192bcd5deb1928'

# Reject
#python3 5g_aka.py -M 466 -N 66 -I 466666100000001 \
#    -K 808182888485868788898a8b8c8d8e8f \
#    -P 97a167ded889b6dfa92d985d77e5c088 \
#    -R 61294093cf25ff6de3e3d8645e2d952e \
#    -A 0af31201291680001a2cf30ebfcf9cc5
#echo 'expect RES: 323ff3173f6923535b4baca6f47c487d'

# test
python3 5g_aka.py -M 466 -N 66 -I 466666100000001 \
    -K 808182888485868788898a8b8c8d8e8f \
    -P 97a167ded889b6dfa92d985d77e5c088 \
    -R 45d9682b874a8be3a25619886b778836 \
    -A b1ab14dffbc68000f5195fd889e60c6b 
echo 'expect RES: '

