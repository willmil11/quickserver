echo "Compiling using gcc..."
echo " + gcc -O3 -march=native quickserve.c -o quickserve -pthread -lssl -lcrypto"
gcc -O3 -march=native quickserver.c -o quickserver -pthread -lssl -lcrypto
echo "Done."
