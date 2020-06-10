#include <chrono>
#include <iostream>
#include <iomanip>
#include <string>
#include <thread>
#include <future>


#include "cryptopp820/cryptlib.h"
#include "cryptopp820/files.h"
#include "cryptopp820/hex.h"
#include "cryptopp820/sha.h"
#include "cryptopp820/hmac.h"

void printCode(std::future<void> end_flag);


int main(int argc, char** argv){

  int c;

  if (argv[1] != NULL && argv[1] == std::string("--get-otp")) {

    std::promise<void> exit_signal;

    std::future<void> end_flag = exit_signal.get_future();

    std::thread counter(&printCode, std::move(end_flag));

    counter.detach();

    std::cout << "Printing codes every seconds, press enter to terminate..." << '\n';

    c = getchar();

    exit_signal.set_value();

  }

  return 0;
}


void printCode(std::future<void> end_flag) {

  const CryptoPP::byte k[] = {
    0x73,0x65,0x63,0x72,0x65,0x74,0x6b,0x65,0x79,0x31,
    0x73,0x65,0x63,0x72,0x65,0x74,0x6b,0x65,0x79,0x32
  };

  CryptoPP::byte m[9];
  std::string digest, code;
  unsigned int offset, decimal;
  std::stringstream stream;


  while (end_flag.wait_for(std::chrono::milliseconds(1)) == std::future_status::timeout) {

    long int periods_since_epoch = (std::chrono::duration_cast< std::chrono::seconds > (std::chrono::system_clock::now().time_since_epoch())).count() / 30;

    strcpy( (char*) m , std::to_string(periods_since_epoch).c_str() );

    CryptoPP::HexEncoder hex(new CryptoPP::StringSink(digest));

    CryptoPP::HMAC<CryptoPP::SHA1> hmac(k, sizeof(k));
    hmac.Update(m, 8);

    CryptoPP::byte d[CryptoPP::HMAC<CryptoPP::SHA1>::DIGESTSIZE];
    hmac.Final(d);

    // std::cout << "Message: ";
    // hex.Put(m, 8);
    // hex.MessageEnd();
    // std::cout << std::endl;

    hex.Put(d, sizeof(d));
    hex.MessageEnd();

    std::cout << digest << '\n';

    stream << std::hex << digest[39];
    stream >> offset;

    stream.str("");
    stream.clear();

    for (int i = 0; i < 8; i++) {
      code = code + digest[2*offset+i];
    }

    stream << std::hex << code;
    stream >> decimal;

    stream.str("");
    stream.clear();

    std::cout << digest << '\n';
    std::cout << code << '\n';
    std::cout << decimal << '\n';

    code.clear();
    digest.clear();





    std::this_thread::sleep_for (std::chrono::seconds(5));
  }
}
