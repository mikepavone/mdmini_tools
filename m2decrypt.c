#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

const char base_key[] = "nY/RHn+XH8T77";

#define MT_SIZE 624
#define MT_MIDDLE 397
#define MT_A 0x9908B0DFU
#define MT_U 11
#define MT_S 7
#define MT_B 0x9D2C5680U
#define MT_T 15
#define MT_C 0xEFC60000U
#define MT_L 18
#define MT_F 1812433253


typedef struct {
	uint32_t mt[MT_SIZE];
	uint32_t index;
} mt19937_state;


uint32_t mt19937(mt19937_state *state)
{
	if (state->index == MT_SIZE) {
		for (int i = 0; i < MT_SIZE; i++)
		{
			uint32_t x = (state->mt[i] & 0x80000000U) | (state->mt[(i + 1) % MT_SIZE] & 0x7FFFFFFF);
			if (x & 1) {
				x = (x >> 1) ^ MT_A;
			} else {
				x >>= 1;
			}
			state->mt[i] = state->mt[(i + MT_MIDDLE) % MT_SIZE] ^ x;
		}
		state->index = 0;
	}
	uint32_t res = state->mt[state->index++];
	res ^= res >> MT_U;
	res ^= (res << MT_S) & MT_B;
	res ^= (res << MT_T) & MT_C;
	res ^= res >> MT_L;
	return res;
}

void mt19937_seed(mt19937_state *state, uint32_t seed)
{
	state->mt[0] = seed;
	for (int i = 1; i < MT_SIZE; i++)
	{
		state->mt[i] = MT_F * (state->mt[i - 1] ^ (state->mt[i - 1] >> 30)) + i;
	}
	state->index = MT_SIZE;
}

void mt19937_seed_array(mt19937_state *state, uint32_t *seed, uint32_t seed_len)
{
	mt19937_seed(state, 19650218);
	int j = 0;
	for (int i = 1; i < MT_SIZE; i++)
	{
		state->mt[i] = (state->mt[i] ^ (state->mt[i - 1] ^ (state->mt[i - 1] >> 30)) * 1664525) + seed[j] + j;
		j++;
		if (j == seed_len) {
			j = 0;
		}
	}
	state->mt[0] = state->mt[MT_SIZE - 1];
	state->mt[1] = (state->mt[1] ^ (state->mt[0] ^ (state->mt[0] >> 30)) * 1664525) + seed[j] + j;
	for (int i = 2; i < MT_SIZE; i++)
	{
		state->mt[i] = (state->mt[i] ^ ((state->mt[i - 1] ^ (state->mt[i - 1] >> 30)) * 1566083941)) - i;
	}
	state->mt[0] = state->mt[MT_SIZE - 1];
	state->mt[1] = (state->mt[1] ^ ((state->mt[0] ^ (state->mt[0] >> 30)) * 1566083941)) - 1;
	state->mt[0] = 0x80000000U;
}

static uint32_t rotleft(uint32_t val, uint32_t shift)
{
	return val << shift | val >> (32-shift);
}

void md5_chunk(uint8_t *chunk, uint32_t *hash)
{
	static const uint32_t k[] = {
		0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
		0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
		0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
		0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
		0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
		0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
		0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
		0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
		0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
		0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
		0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
		0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
		0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
		0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
		0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
		0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
	};
	static const uint32_t s[] = {
		7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
		5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
		4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
		6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
	};
	uint32_t m[16];
	for (int i = 0; i < 64; i += 4)
	{
		m[i >> 2] = chunk[i] | chunk[i + 1] << 8 | chunk[i + 2] << 16 | chunk[i + 3] << 24;
	}
	uint32_t a = hash[0], b = hash[1], c = hash[2], d = hash[3];
	for (int i = 0; i < 16; i++)
	{
		uint32_t f = (b & c) | ((~b) & d);
		f += a + k[i] + m[i];
		a = d;
		d = c;
		c = b;
		b = b + rotleft(f, s[i]);
	}
	for (int i = 16; i < 32; i++)
	{
		uint32_t f = (d & b) | ((~d) & c);
		int g = (i * 5 + 1) & 15;
		f += a + k[i] + m[g];
		a = d;
		d = c;
		c = b;
		b = b + rotleft(f, s[i]);
	}
	for (int i = 32; i < 48; i++)
	{
		uint32_t f = b ^ c ^ d;
		int g = (i * 3 + 5) & 15;
		f += a + k[i] + m[g];
		a = d;
		d = c;
		c = b;
		b = b + rotleft(f, s[i]);
	}
	for (int i = 48; i < 64; i++)
	{
		uint32_t f = c ^ (b | ~d);
		int g = (i * 7) & 15;
		f += a + k[i] + m[g];
		a = d;
		d = c;
		c = b;
		b = b + rotleft(f, s[i]);
	}
	hash[0] += a;
	hash[1] += b;
	hash[2] += c;
	hash[3] += d;
}

void md5(uint8_t *data, uint64_t size, uint8_t *out)
{
	uint32_t hash[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
	uint8_t last[128];
	uint32_t last_size = 0;
	if ((size & 63) != 0) {
		for (uint32_t src = size - (size & 63); src < size; src++)
		{
			last[last_size++] = data[src];
		}
	}
	uint64_t bitsize = size * 8;
	size -= last_size;
	last[last_size++] = 0x80;
	while ((last_size & 63) != 56)
	{
		last[last_size++] = 0;
	}


	last[last_size++] = bitsize;
	last[last_size++] = bitsize >> 8;
	last[last_size++] = bitsize >> 16;
	last[last_size++] = bitsize >> 24;
	last[last_size++] = bitsize >> 32;
	last[last_size++] = bitsize >> 40;
	last[last_size++] = bitsize >> 48;
	last[last_size++] = bitsize >> 56;

	for (uint64_t cur = 0; cur < size; cur += 64)
	{
		md5_chunk(data + cur, hash);
	}
	for (uint64_t cur = 0; cur < last_size; cur += 64)
	{
		md5_chunk(last + cur, hash);
	}
	for (uint32_t cur = 0; cur < 16; cur += 4)
	{
		uint32_t val = hash[cur >> 2];
		out[cur] = val;
		out[cur+1] = val >> 8;
		out[cur+2] = val >> 16;
		out[cur+3] = val >> 24;
	}
}

void bin_to_hex(uint8_t *output, uint8_t *input, uint64_t size)
{
	while (size)
	{
		uint8_t digit = *input >> 4;
		digit += digit > 9 ? 'a' - 0xa : '0';
		*(output++) = digit;
		digit = *(input++) & 0xF;
		digit += digit > 9 ? 'a' - 0xa : '0';
		*(output++) = digit;
		size--;
	}
	*(output++) = 0;
}

int main(int argc, char **argv)
{
	char *base_name = argv[1];
	for(char *cur = argv[1]; *cur; ++cur)
	{
		if (*cur == '/') {
			base_name = cur + 1;
		}
	}
	size_t key_size = strlen(base_key) + strlen(base_name);
	char *key = malloc(key_size + 1);
	memcpy(key, base_key, strlen(base_key));
	char *dst, *src;
	for (dst = key + strlen(base_key), src = base_name; *src; ++dst, ++src)
	{
		*dst = tolower(*src);
	}
	*dst = 0;

	uint8_t hash[16];
	md5(key, key_size, hash);
	uint32_t mt_init[4];
	for (int i = 0; i < 16; i += 4)
	{
		mt_init[i >> 2] = hash[i] | hash[i + 1] << 8 | hash[i + 2] << 16 | hash[i + 3] << 24;
	}
	mt19937_state mt;
	mt19937_seed_array(&mt, mt_init, 4);
	uint8_t xorbytes[64];
	for (int i = 0; i < 64; i += 4)
	{
		uint32_t val = mt19937(&mt);
		xorbytes[i] = val;
		xorbytes[i + 1] = val >> 8;
		xorbytes[i + 2] = val >> 16;
		xorbytes[i + 3] = val >> 24;
	}
	uint8_t buffer[64];
	FILE *f = fopen(argv[1], "rb");
	fseek(f, 8, SEEK_CUR);
	FILE *out = fopen("out.bin", "wb");
	size_t bytes;
	for (;;)
	{
		size_t bytes = fread(buffer, 1, sizeof(buffer), f);
		if (!bytes) {
			break;
		}
		for (size_t i = 0; i < bytes; i++)
		{
			buffer[i] ^= xorbytes[i];
		}
		fwrite(buffer, 1, bytes, out);
	}
	return 0;
}
