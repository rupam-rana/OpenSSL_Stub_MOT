// OpenSSL_Stub.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <openssl/evp.h>

#define MAX_PRINT_STRING_LEN 1024

char bit_string[MAX_PRINT_STRING_LEN];

uint8_t nibble_to_hex_char(uint8_t nibble);

char* string_to_hex_string(const void *s, int length);

void print_byte_arr(char* description, unsigned char* byte_arr, unsigned int byte_arr_len);

void cipher_generator(EVP_CIPHER_CTX* cipher_obj, unsigned char* iv, unsigned char* out_cipher, int* cipher_len);

int main()
{
	EVP_CIPHER_CTX* cipher_obj = NULL;

	unsigned char key[] = { 0x17, 0xf1, 0x34, 0x8f, 0x4f, 0xbc, 0x25, 0x75, 0x9d, 0x09, 0x14, 0x68, 0xfa, 0x02, 0x52, 0x8e },
		iv1[] = { 0x5d, 0xf8, 0xa2, 0x9b, 0x96, 0xcb, 0x00, 0xc5, 0x70, 0x32, 0x29, 0x3c, 0x00, 0x00, 0x00, 0x00 },
		iv2[] = { 0x5d, 0xf8, 0xa2, 0x9b, 0x96, 0xcb, 0x00, 0xc7, 0x70, 0x32, 0x29, 0x3c, 0x00, 0x00, 0x00, 0x00 },
		iv3[] = { 0x5d, 0xf8, 0xa2, 0x9b, 0x96, 0xcb, 0x00, 0xc4, 0x70, 0x32, 0x29, 0x3c, 0x00, 0x00, 0x00, 0x00 },
		iv4[] = { 0x5d, 0xf8, 0xa2, 0x9b, 0x96, 0xcb, 0x00, 0xc6, 0x70, 0x32, 0x29, 0x3c, 0x00, 0x00, 0x00, 0x00 },
		iv5[] = { 0x5d, 0xf8, 0xa2, 0x9b, 0x96, 0xcb, 0x00, 0xc0, 0x70, 0x32, 0x29, 0x3c, 0x00, 0x00, 0x00, 0x00 },
		iv6[] = { 0x5d, 0xf8, 0xa2, 0x9b, 0x96, 0xcb, 0x00, 0xc1, 0x70, 0x32, 0x29, 0x3c, 0x00, 0x00, 0x00, 0x00 },

		out_buff[16] = { 0, };

	int ret = -1, cipher_len = 0, count = 0;

	std::cout << "Hello World! START" << std::endl;

	std::cout << "cipher EVP_aes_128_ctr type: " << EVP_aes_128_ctr() << std::endl;

	print_byte_arr((char*)"key:", key, sizeof(key));

	cipher_obj = EVP_CIPHER_CTX_new();

	ret = EVP_EncryptInit_ex(cipher_obj, EVP_aes_128_ctr(), NULL, key, NULL);

	std::cout << std::endl;

	std::cout << "count: " << ++count << std::endl;
	cipher_len = 16;
	memset(out_buff, 0, 16);
	cipher_generator(cipher_obj, iv1, out_buff, &cipher_len);

	std::cout << "count: " << ++count << std::endl;
	cipher_len = 12;
	memset(out_buff, 0, 16);
	cipher_generator(cipher_obj, iv2, out_buff, &cipher_len);

	std::cout << "count: " << ++count << std::endl;
	cipher_len = 0;
	memset(out_buff, 0, 16);
	cipher_generator(cipher_obj, iv3, out_buff, &cipher_len);

	std::cout << "count: " << ++count << std::endl;
	cipher_len = 16;
	memset(out_buff, 0, 16);
	cipher_generator(cipher_obj, iv4, out_buff, &cipher_len);

	std::cout << "count: " << ++count << std::endl;
	cipher_len = 12;
	memset(out_buff, 0, 16);
	cipher_generator(cipher_obj, iv5, out_buff, &cipher_len);

	std::cout << "count: " << ++count << std::endl;
	cipher_len = 0;
	memset(out_buff, 0, 16);
	cipher_generator(cipher_obj, iv6, out_buff, &cipher_len);

	std::cout << "Hello World! END" << std::endl;
}

void cipher_generator(EVP_CIPHER_CTX* cipher_obj, unsigned char* iv, unsigned char* out_cipher, int* cipher_len)
{
	int len = 0, ret = -1;

	std::cout << "cipher_generator entered with" << std::endl;
	print_byte_arr((char*)"iv: ", iv, 16);
	print_byte_arr((char*)"out_cipher: ", out_cipher, *cipher_len);
	std::cout << "cipher_len: " << *cipher_len << std::endl;

	ret = EVP_EncryptInit_ex(cipher_obj, NULL, NULL, NULL, iv);
	std::cout << "cipher_generator EVP_EncryptInit_ex ret:" << ret << std::endl;

	ret = EVP_EncryptUpdate(cipher_obj, out_cipher, &len, out_cipher, *cipher_len);
	std::cout << "cipher_generator EVP_EncryptUpdate ret:" << ret << std::endl;
	*cipher_len = len;

	ret = EVP_EncryptFinal(cipher_obj, out_cipher, &len);
	*cipher_len += len;
	std::cout << "cipher_generator EVP_EncryptFinal ret:" << ret << std::endl;

	std::cout << "cipher_generator exit with" << std::endl;
	print_byte_arr((char*)"out_cipher: ", out_cipher, *cipher_len);
	std::cout << "cipher_len: " << *cipher_len << std::endl << std::endl;
}

void print_byte_arr(char* description, unsigned char* byte_arr, unsigned int byte_arr_len)
{
	std::cout << description << " " << string_to_hex_string(byte_arr, byte_arr_len) << std::endl;
}

uint8_t nibble_to_hex_char(uint8_t nibble)
{
	char buf[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
					 '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
	return buf[nibble & 0xF];
}

char* string_to_hex_string(const void *s, int length)
{
	const uint8_t *str = (const uint8_t *)s;
	int i;

	/* double length, since one octet takes two hex characters */
	length *= 2;

	/* truncate string if it would be too long */
	if (length > MAX_PRINT_STRING_LEN)
		length = MAX_PRINT_STRING_LEN - 2;

	for (i = 0; i < length; i += 2) {
		bit_string[i] = nibble_to_hex_char(*str >> 4);
		bit_string[i + 1] = nibble_to_hex_char(*str++ & 0xF);
	}
	bit_string[i] = 0; /* null terminate string */
	return bit_string;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
