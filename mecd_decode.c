#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <opus.h>

typedef struct {
	char     type[4];
	uint32_t size;
} chunk_header;

typedef struct {
	uint32_t hi;
	uint32_t lo;
} decoder_state;

void init_decoder_hi(decoder_state *state, uint32_t seed)
{
	state->hi = seed;
	if (seed > 0xffffff4dU) {
		state->hi += 0xB2;
	}
}

void init_decoder(decoder_state *state, uint32_t seed, uint32_t seed_low)
{
	state->lo = seed_low;
	if (seed_low) {
		init_decoder_hi(state, seed);
	}
}

uint32_t decoder_next(decoder_state *state)
{
	if (!state->lo) {
		return 0;
	}
	uint64_t tmp64 = (uint64_t)state->lo * 0xffffff4EULL + (uint64_t)state->hi;
	state->lo = tmp64;
	state->hi = tmp64 >> 32;
	tmp64 = (uint64_t)state->lo + (uint64_t)state->hi;
	state->lo = tmp64;
	if (tmp64 & 0x100000000ULL) {
		state->lo++;
		state->hi++;
	}
	state->lo = 0xFFFFFFFEU - state->lo;//((uint32_t)sum64);
	return state->lo;
}

void decode_in_place(decoder_state *state, void *buf, uint32_t size)
{
	uint32_t *as_u32 = buf;
	uint8_t *as_u8 = buf;
	uint32_t size_in_u32s = size / sizeof(uint32_t);
	for (uint32_t i = 0; i < size_in_u32s; i++)
	{
		as_u32[i] ^= decoder_next(state);
	}
	uint32_t key;
	for (uint32_t i = size_in_u32s * 4; i < size; i++)
	{
		if (!(i & 3)) {
			key = decoder_next(state);
		}
		as_u8[i] ^= key;
		key >>= 8;
	}
}

int16_t decode_buffer[48 * 120 * 2];

int main(int argc, char **argv)
{
	FILE *f = fopen(argv[1], "rb");
	fseek(f, 8, SEEK_CUR);
	decoder_state state = {0,0};
	uint8_t has_info = 0;
	int error;
	OpusDecoder *decoder = opus_decoder_create(48000, 2, &error);
	printf("opus_decoder_create: %p, error = %d\n", decoder, error);
	
	for (;;)
	{
		chunk_header h;
		size_t els_read = fread(&h, sizeof(chunk_header), 1, f);
		if (els_read < 1 || !(h.type[0] | h.type[1] | h.type[2] | h.type[3])) {
			break;
		}
		printf("Chunk %c%c%c%c  size: %u\n", h.type[0], h.type[1], h.type[2], h.type[3], h.size);
		if (!memcmp(h.type, "arch", 4)) {
			char *arch = calloc(1, h.size);
			els_read = fread(arch, 1, h.size, f);
			if (els_read != h.size) {
				break;
			}
			if (arch[h.size-1] != 0) {
				fprintf(stderr, "arch not properly terminated, found %X", arch[h.size-1]);
				arch[h.size-1] = 0;
			}
			printf("\t%s\n", arch);
			free(arch);
		} else if (!memcmp(h.type, "info", 4)) {
			if (h.size < 0x10 || has_info) {
				fseek(f, h.size, SEEK_CUR);
				continue;
			}
			has_info = 1;
			size_t num_els = h.size / sizeof(uint32_t);
			uint32_t *els = calloc(sizeof(uint32_t), num_els);
			size_t els_read = fread(els, sizeof(uint32_t), num_els, f);
			init_decoder(&state, h.size, els[num_els - 1]);
			decoder_state my_state = state;
			int track_num = 1;
			FILE *cuef = fopen("image.cue", "w");
			fprintf(cuef, "FILE \"data.bin\" BINARY\n");
			uint8_t flag;
			for (size_t i = 0; i < els_read - 1; i++)
			{
				uint32_t decoded = els[i] ^ decoder_next(&my_state);
				if (!i) {
					printf("Num tracks: %d\n", decoded);
				} else {
					uint32_t m,s,f;
					switch (i%3)
					{
					case 1:
						flag = decoded >> 31;
						decoded &= 0x7FFFFFFF;
						printf("Pre-Gap Length: ");
						break;
					case 2:
						printf(", Start: ");
						break;
					case 0:
						printf(", Length: ");
						break;
					}
					f = decoded % 75;
					s = decoded / 75;
					m = s / 60;
					s = s % 60;
					printf("%02d:%02d:%02d", m, s, f);
					switch (i%3)
					{
					case 1:
						printf(", IsAudio: %d", flag);
						break;
					case 2:
						fprintf(cuef, "  TRACK %02d %s\n", track_num++, flag ? "AUDIO" : "MODE1/2048");
						if (flag) {
							fprintf(cuef, "    INDEX 00 %02d:%02d:%02d\n", m, s, f);
							s += 2;
							if (s >= 60) {
								s -= 60;
								m++;
							}
							fprintf(cuef, "    INDEX 01 %02d:%02d:%02d\n", m, s, f);
						} else {
							fprintf(cuef, "    INDEX 01 %02d:%02d:%02d\n", m, s, f);
							fprintf(cuef, "FILE \"audio.wav\" WAVE\n");
						}
						break;
					case 0:
						putchar('\n');
						break;
					}
				}
			}
			free(els);
			fclose(cuef);
		} else if (!memcmp(h.type, "offs", 4)) {
			if (h.size < 0x14) {
				fseek(f, h.size, SEEK_CUR);
				continue;
			}
			init_decoder_hi(&state, h.size);
			decoder_state my_state = state;
			size_t num_els = h.size / sizeof(uint32_t);
			uint32_t *els = calloc(sizeof(uint32_t), num_els);
			size_t els_read = fread(els, sizeof(uint32_t), num_els, f);
			long old_pos = ftell(f);
			FILE *data_file = fopen("data.bin", "wb");
			FILE *audio_file = fopen("audio.bin", "wb");
			uint32_t prev;
			uint32_t data_blocks = 0;
			for (size_t i = 0, cur_block = 0; i < els_read; i++)
			{
				uint32_t decoded = els[i] ^ decoder_next(&my_state);
				switch (i)
				{
				case 2:
					printf("data_blocks: %d\n", decoded);
					data_blocks = decoded;
					break;
				case 3:
					printf("audio_blocks: %d\n", decoded);
					break;
				default:
					printf("%lu: %X\n", i, decoded);
					if (i > 4) {
						decoder_state block_state = state;
						uint32_t seed;
						if (cur_block < data_blocks) {
							seed = cur_block | 0x10000;
						} else {
							seed = (cur_block - data_blocks) | 0x20000;
						}
						init_decoder_hi(&block_state, seed);
						uint32_t size = decoded - prev;
						if (!size && cur_block >= data_blocks) {
							//TODO: use silence from audz instead
							int16_t sample[2] = {0,0};
							for (int j = 0; j < 48000; j++)
							{
								fwrite(sample, 2, sizeof(int16_t), audio_file);
							}
						} else {
							void *block = calloc(1, size);
							fseek(f, prev, SEEK_SET);
							size_t bytes_read = fread(block, 1, size, f);
							decode_in_place(&block_state, block, bytes_read);
							if (cur_block < data_blocks) {
								fwrite(block, 1, bytes_read, data_file);
							} else {
								uint8_t *bytes = block;
								uint32_t num_packets = bytes[0];
								printf("num opus packets: %u\n", num_packets);
								uint8_t *cur = bytes + 1;
								for (uint32_t i = 0; i < num_packets; i++)
								{
									if (*cur & 0x80) {
										cur += 2;
									} else {
										cur++;
									}
								}
								uint8_t *sizes_end = cur;
								uint8_t *cur_size = bytes + 1;
								for (uint8_t *sizes_end = cur, *cur_size = bytes + 1; cur_size != sizes_end; cur_size++)
								{
									uint32_t size = *cur_size;
									if (size & 0x80) {
										size &= 0x7F;
										cur_size++;
										size |= *cur_size << 7;
									}
									int decoded = opus_decode(decoder, cur, size, decode_buffer, 48 * 120, 0);
									if (decoded > 0) {
										printf("encoded size: %u, decoded size: %d, offset: %ld\n", size, decoded, cur - bytes);
										fwrite(decode_buffer, 2 * sizeof(int16_t), decoded, audio_file);
									} else {
										printf("opus_decode error %d, encoded_size: %u, first_byte %X, offset: %ld\n", decoded, size, *cur, cur - bytes);
									}
									cur += size;
								}
								//fwrite(block, 1, bytes_read, audio_file);
							}
						}
						cur_block++;
					}
					prev = decoded;
					break;
				}
			}
			free(els);
			fseek(f, old_pos, SEEK_SET);
			fclose(data_file);
			fclose(audio_file);
		} else if (!memcmp(h.type, "audz", 4)) {
			if (h.size < 9) {
				fseek(f, h.size, SEEK_CUR);
				continue;
			}
			init_decoder_hi(&state, h.size);
			decoder_state my_state = state;
			size_t num_els = h.size / sizeof(uint32_t);
			uint8_t *audz = calloc(1, h.size);
			size_t bytes_read = fread(audz, 1, h.size, f);
			num_els = bytes_read / 4;
			if (num_els > 2) {
				num_els = 2;
			}
			uint32_t *els = (uint32_t *)audz;
			for (size_t i = 0; i < num_els; i++)
			{
				uint32_t decoded = els[i] ^ decoder_next(&my_state);
				if (i) {
					printf("opus_padding_samples: %u\n", decoded);
				} else {
					printf("total_opus_samples: %u\n", decoded);
				}
			}
			uint32_t key;
			for (size_t i = num_els * 4; i < bytes_read; i++)
			{
				if (!(i & 3)) {
					key = decoder_next(&my_state);
				}
				uint8_t decoded = audz[i] ^ key;
				key >>= 8;
				printf((i & 3) == 3 ? "%02X\n" : "%02X ", decoded);
			}
			if (bytes_read & 3) {
				putchar('\n');
			}
			free(audz);
		} else {
			fseek(f, h.size, SEEK_CUR);
		}
	}
	return 0;
}