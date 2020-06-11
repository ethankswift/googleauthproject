all: crypto totp

crypto:
	cd cryptopp820; make default

totp: main.cpp
	g++ -DNDEBUG -g2 -O2 -I . -pthread main.cpp -o totp ./cryptopp820/libcryptopp.a

clean:
	rm -f totp

allclean:
	(rm -f totp)
	(cd cryptopp820; make clean)
