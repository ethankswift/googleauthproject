all: crypto qrgen totp

crypto:
	cd cryptopp820; make default

qrgen:
	cd qrcodegen; make qrcode.o

totp: main.cpp
	g++ -std=c++11 -DNDEBUG -g2 -O2 -I . -pthread main.cpp -o totp ./cryptopp820/libcryptopp.a ./qrcodegen/qrcode.o

clean:
	rm -f totp

allclean:
	(rm -f totp)
	(cd qrcodegen; make clean)
	(cd cryptopp820; make clean)
