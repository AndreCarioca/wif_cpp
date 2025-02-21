/*
[+] Desenvolvido por AndreCarioca [+]
*/
#include <iostream>
#include <string>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <vector>
#include <openssl/sha.h>
#include <gmp.h>

std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

static const char* BASE58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

std::string base58Encode(const std::vector<uint8_t>& data) {
    mpz_t bn;
    mpz_init(bn);

    mpz_import(bn, data.size(), 1, 1, 0, 0, data.data());

    std::string result;
    mpz_t quotient, remainder;
    mpz_init(quotient);
    mpz_init(remainder);

    while (mpz_cmp_ui(bn, 0) > 0) {
        mpz_fdiv_qr_ui(bn, remainder, bn, 58);
        unsigned long index = mpz_get_ui(remainder);
        result = BASE58_CHARS[index] + result;
    }

    // Add leading '1' for each leading zero byte
    for (size_t i = 0; i < data.size() && data[i] == 0; i++) {
        result = '1' + result;
    }

    mpz_clear(quotient);
    mpz_clear(remainder);
    mpz_clear(bn);
    return result;
}

std::string convertPrivateKey(const std::string& hex_key) {
    mpz_t n, key, result;
    mpz_init(n);
    mpz_init(key);
    mpz_init(result);

    // Ordem da curva secp256k1 - 1
    mpz_set_str(n, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    mpz_set_str(key, hex_key.c_str(), 16);

    // Calcula result = N - key
    mpz_sub(result, n, key);

    // Converte para string hex
    char* result_str = mpz_get_str(nullptr, 16, result);
    std::string result_hex = result_str;
    free(result_str);

    // Padding com zeros
    while (result_hex.length() < 64) {
        result_hex = "0" + result_hex;
    }

    mpz_clear(n);
    mpz_clear(key);
    mpz_clear(result);

    return result_hex;
}

std::string toWIF(const std::string& hex_key) {
    // Converte a chave primeiro
    std::string converted_key = convertPrivateKey(hex_key);
    //std::cout << "Converted key: " << converted_key << std::endl; // Debug output

    // Converte hex para bytes
    std::vector<uint8_t> key_bytes = hexToBytes(converted_key);

    // Prepara o vetor final com version byte e compression flag
    std::vector<uint8_t> extended;
    extended.push_back(0x80); // Mainnet private key
    extended.insert(extended.end(), key_bytes.begin(), key_bytes.end());
    extended.push_back(0x01); // Compressed public key flag

    // Debug output
    //std::cout << "Extended bytes (including version and compression): ";
    //for(const auto& byte : extended) {
    //    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    //}
    //std::cout << std::endl;

    // Calcula o double SHA256 para o checksum
    uint8_t hash1[SHA256_DIGEST_LENGTH];
    uint8_t hash2[SHA256_DIGEST_LENGTH];

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, extended.data(), extended.size());
    SHA256_Final(hash1, &sha256);

    SHA256_Init(&sha256);
    SHA256_Update(&sha256, hash1, SHA256_DIGEST_LENGTH);
    SHA256_Final(hash2, &sha256);

    // Adiciona os primeiros 4 bytes do checksum
    extended.insert(extended.end(), hash2, hash2 + 4);

    // Debug output of final bytes before Base58
    //std::cout << "Final bytes (including checksum): ";
    //for(const auto& byte : extended) {
    //    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    //}
    //std::cout << std::endl;

    // Converte para Base58
    return base58Encode(extended);
}

void saveToFile(const std::string& pointSecp256k1, const std::string& privateKey, const std::string& wifKey, const std::string& filename) {
    std::ofstream file(filename);
    if (file.is_open()) {
        file << "Point secp256k1: " << pointSecp256k1 << std::endl;
        file << "Private Key: " << privateKey << std::endl;
        file << "WIF Key: " << wifKey << std::endl;
        file.close();
        std::cout << "Keys saved to " << filename << std::endl;
    } else {
        std::cerr << "Unable to open file for writing" << std::endl;
    }
}

int main(int argc, char* argv[]) {
    // Verifica se o número de argumentos é suficiente
    if (argc < 2) {
        std::cerr << "Uso: " << argv[0] << " hex_string_64bit | EX: " << argv[0] << " fffffffffffffffffffffffffffffffebaaedce6af48a0348ed63b30b6f37f93" << std::endl;
        return 1; // Retorna um código de erro
    }

    // O primeiro argumento (argv[1]) é a string hexadecimal
    std::string hextemp = argv[1];

    // Agora você pode usar a string hextemp no seu código
    //std::cout << "String hexadecimal inserida: " << hextemp << std::endl;

    //std::string hextemp = "fffffffffffffffffffffffffffffffebaaedce6af48a0348ed63b30b6f37f93";
    std::string converted_key = convertPrivateKey(hextemp);
    std::string wif = toWIF(hextemp);

    // Salva as chaves em um arquivo
    saveToFile(hextemp, converted_key, wif, "WIF_KEY.txt");

    // Mostra as chaves no console também
    std::cout << "Point secp256k1: " << hextemp << std::endl;
    std::cout << "Private Key: " << converted_key << std::endl;
    std::cout << "WIF Key: " << wif << std::endl;

    return 0;
}
// compilar:
// g++ wif.cpp -o wif -lgmp -lssl -lcrypto

// usar:
//./wif Private_Key_no_KEYFOUNDKEYFOUND.txt
