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
    0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,
    0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30
  };

  CryptoPP::byte m[] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
  };

  // CryptoPP::byte m[17];
  std::string digest, code;
  unsigned int offset, decimal;
  std::stringstream stream;


  while (end_flag.wait_for(std::chrono::milliseconds(1)) == std::future_status::timeout) {

    long int periods_since_epoch = (std::chrono::duration_cast< std::chrono::seconds > (std::chrono::system_clock::now().time_since_epoch())).count() / 30;

    // strcpy( (char*) m , std::to_string(periods_since_epoch).c_str() );

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

    stream << std::hex << digest[39];
    stream >> offset;

    stream.str("");
    stream.clear();

    for (int i = 0; i < 8; i++) {
      code = code + digest[2*offset+i];
    }

    switch (code[0]) {
      case '8':
      code[0] = '0';
      break;
      case '9':
      code[0] = '1';
      break;
      case 'A':
      code[0] = '2';
      break;
      case 'B':
      code[0] = '3';
      break;
      case 'C':
      code[0] = '4';
      break;
      case 'D':
      code[0] = '5';
      break;
      case 'E':
      code[0] = '6';
      break;
      case 'F':
      code[0] = '7';
      break;

    }

    stream << std::hex << code;
    stream >> decimal;

    stream.str("");
    stream.clear();

    printf("message: ");
    for (size_t i = 0; i < sizeof(m); i++) {
      printf("%d", m[i]);
    }
    printf("\n");
    std::cout << "digest: " << digest << '\n';
    std::cout << "hexout: " << code << '\n';
    std::cout << "code: " << decimal << '\n';

    code.clear();
    digest.clear();





    std::this_thread::sleep_for (std::chrono::seconds(5));
  }
}
