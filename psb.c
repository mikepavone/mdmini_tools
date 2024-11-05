#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

//From: https://gitlab.com/modmyclassic/sega-mega-drive-mini/marchive-batch-tool/-/blob/master/psb_v4.md?ref_type=heads
typedef struct 
{
    char magicNumber[4]; // "PSB\0"
    uint16_t version;
    uint16_t flags;
    uint32_t ofstKeyOffsetArray;
    uint32_t ofstKeyEntity;
    uint32_t ofstStringOffsetArray;
    uint32_t ofstStringEntity;
    uint32_t ofstStreamOffsetArray;
    uint32_t ofstStreamSizeArray;
    uint32_t ofstStreamEntity;
    uint32_t ofstRootValue;
    // PSB v3
    uint32_t checksum;
    // PSB v4
    uint32_t ofstBStreamOffsetArray;
    uint32_t ofstBStreamSizeArray;
    uint32_t ofstBStreamEntity;
} psb_header;

typedef struct
{
	int64_t *valueOffsets;
	int64_t *tree;
	int64_t *tails;
	int64_t num_entries;
	int64_t num_nodes;
} key_entity;

typedef struct
{
	int64_t *offsets;
	int64_t *sizes;
	int64_t num_streams;
} stream_info;

int64_t parse_int_type(uint8_t type, uint8_t *buf, size_t size, uint8_t **after)
{
	switch (type)
	{
	case 4:
		*after = buf;
		return 0;
	case 5: {
		if (size < 1) {
			return 0;
		}
		*after = buf + 1;
		int8_t v = buf[0];
		return v;
	}
	case 6: {
		if (size < 2) {
			return 0;
		}
		*after = buf + 2;
		int16_t v = buf[0] | buf[1] << 8;
		return v;
	}
	case 7: {
		if (size < 3) {
			return 0;
		}
		*after = buf + 3;
		int32_t v = buf[0] | buf[1] << 8 | buf[2] << 16;
		if (v & 0x800000) {
			v |= 0xFF000000;
		}
		return v;
	}
	case 8: {
		if (size < 4) {
			return 0;
		}
		*after = buf + 4;
		int32_t v = buf[0] | buf[1] << 8 | buf[2] << 16 | buf[3] << 24;
		return v;
	}
	case 9: {
		if (size < 5) {
			return 0;
		}
		*after = buf + 5;
		int64_t v = ((int64_t)buf[0]) | ((int64_t)buf[1]) << 8 | ((int64_t)buf[2]) << 16 | ((int64_t)buf[3]) << 24 | ((int64_t)buf[4]) << 32;
		if (v & 0x8000000000LL) {
			v |= 0xFFFFFF00000000ULL;
		}
		return v;
	}
	case 10: {
		if (size < 6) {
			return 0;
		}
		*after = buf + 6;
		int64_t v = ((int64_t)buf[0]) | ((int64_t)buf[1]) << 8 | ((int64_t)buf[2]) << 16 | ((int64_t)buf[3]) << 24 | ((int64_t)buf[4]) << 32 | ((int64_t)buf[5]) << 40;
		if (v & 0x800000000000LL) {
			v |= 0xFFFF0000000000ULL;
		}
		return v;
	}
	case 11: {
		if (size < 7) {
			return 0;
		}
		*after = buf + 7;
		int64_t v = ((int64_t)buf[0]) | ((int64_t)buf[1]) << 8 | ((int64_t)buf[2]) << 16 | ((int64_t)buf[3]) << 24 | ((int64_t)buf[4]) << 32 | ((int64_t)buf[5]) << 40 | ((int64_t)buf[6]) << 48;
		if (v & 0x80000000000000LL) {
			v |= 0xFF000000000000ULL;
		}
		return v;
	}
	case 12: {
		if (size < 8) {
			return 0;
		}
		*after = buf + 8;
		return ((int64_t)buf[0]) | ((int64_t)buf[1]) << 8 | ((int64_t)buf[2]) << 16 | ((int64_t)buf[3]) << 24 | ((int64_t)buf[4]) << 32 | ((int64_t)buf[5]) << 40 | ((int64_t)buf[6]) << 48 | ((int64_t)buf[7]) << 56;
	}
	case 13:
		if (size < 1) {
			return 0;
		}
		*after = buf + 1;
		return buf[0];
	case 14:
		if (size < 2) {
			return 0;
		}
		*after = buf + 2;
		return buf[0] | buf[1] << 8;
	case 15:
		if (size < 3) {
			return 0;
		}
		*after = buf + 3;
		return buf[0] | buf[1] << 8 | buf[2] << 16;
	case 16:
		if (size < 4) {
			return 0;
		}
		*after = buf + 4;
		return buf[0] | buf[1] << 8 | buf[2] << 16 | (int64_t)buf[3] << 24;
	default:
		*after = buf;
		return 0;
	}
}

int64_t parse_int(uint8_t *buf, size_t size, uint8_t **after)
{
	if (size < 1) {
		*after = buf;
		return 0;
	}
	return parse_int_type(*buf, buf + 1, size - 1, after);
}

int64_t *parse_array(uint8_t *buf, size_t size, int64_t *size_out, uint8_t **after)
{
	*size_out = parse_int(buf, size, after);
	if (*size_out < 0) {
		*after = buf;
		return NULL;
	}
	size -= *after - buf;
	buf = *after;
	if (!size) {
		*after = buf;
		return NULL;
	}
	int64_t *ret = calloc(*size_out, sizeof(int64_t));
	uint8_t el_type = *(buf++);
	size--;
	for (int64_t i = 0; i < *size_out; i++)
	{
		ret[i] = parse_int_type(el_type, buf, size, after);
		size -= *after - buf;
		buf = *after;
	}
	return ret;
}

char *key_name(key_entity *keys, int64_t index, char **to_free, char *name_buf, size_t name_buf_size)
{
	char *name = name_buf;
	int char_index = name_buf_size - 1;
	name[char_index] = 0;
	int64_t current = keys->tree[keys->tails[index]];
	while (current > 0 && current < keys->num_nodes)
	{
		char_index--;
		if (char_index < 0) {
			char_index = name_buf_size;
			name_buf_size *= 2;
			char *tmp = calloc(1, name_buf_size);
			memcpy(tmp + char_index, name_buf, char_index);
			name = tmp;
		}
		int64_t parent = keys->tree[current];
		name[char_index] = current - keys->valueOffsets[parent];
		current = parent;
	}
	*to_free = name == name_buf ? NULL : name;
	return name + char_index;
}

int main(int argc, char **argv)
{
	FILE *f = fopen(argv[1], "rb");
	if (!f) {
		fprintf(stderr, "Failed to open %s\n", argv[1]);
		return 1;
	}
	int retval = 0;
	size_t buf_size = 16 * 1024;
	uint8_t *buffer = malloc(buf_size);
	size_t size = 0;
	for(;;)
	{
		size_t bytes = fread(buffer + size, 1, buf_size - size, f);
		if (!bytes) {
			break;
		}
		size += bytes;
		if (size != buf_size) {
			break;
		}
		
		buf_size *= 2;
		buffer = realloc(buffer, buf_size);
	}
	psb_header *header = (psb_header *)buffer;
	if (memcmp("PSB", header->magicNumber, sizeof(header->magicNumber))) {
		fprintf(stderr, "Not a PSB file - %c%c%c%X\n", header->magicNumber[0], header->magicNumber[1], header->magicNumber[2], header->magicNumber[3]);
		retval = 1;
		goto cleanup;
	}
	printf("PSB version %d\n", header->version);
	if (header->version < 2) {
		fputs("Unsupported version", stderr);
		retval = 1;
		goto cleanup;
	}
	key_entity keys;
	uint8_t *after;
	keys.valueOffsets = parse_array(buffer + header->ofstKeyEntity, size - header->ofstKeyEntity, &keys.num_nodes, &after);
	int64_t num_els;
	keys.tree = parse_array(after, size - (after - buffer), &num_els, &after);
	if (num_els != keys.num_nodes) {
		fprintf(stderr, "Value offsets array has %" PRId64 " entries, but tree has %" PRId64 " entries\n", keys.num_nodes, num_els);
		retval = 1;
		goto cleanup;
	}
	keys.tails = parse_array(after, size - (after - buffer), &keys.num_entries, &after);
	for (int64_t i = 0; i < keys.num_entries; i++)
	{
		char name_buf[128];
		char *to_free;
		printf("%" PRId64 ": %s\n", i, key_name(&keys, i, &to_free, name_buf, sizeof(name_buf)));
		free(to_free);
	}
	int64_t num_root_keys;
	//TODO: very root object is an object
	int64_t *rootKeyIndices = parse_array(buffer + header->ofstRootValue + 1, size - 1 - header->ofstRootValue, &num_root_keys, &after);
	int64_t *rootOffsets = parse_array(after, size - (after - buffer), &num_els, &after);
	if (num_els != num_root_keys) {
		fprintf(stderr, "Object key index array %" PRId64 " entries, but offfset array has %" PRId64 " entries\n", num_root_keys, num_els);
		retval = 1;
		goto cleanup;
	}
	puts("Root:");
	uint8_t *file_info = NULL;
	for (int64_t i = 0; i < num_root_keys; i++)
	{
		char name_buf[128];
		char *to_free;
		char *name = key_name(&keys, rootKeyIndices[i], &to_free, name_buf, sizeof(name_buf));
		printf("\t%s - offset: %" PRId64 ", type: %d\n", name, rootOffsets[i], after[rootOffsets[i]]);
		if (!strcmp(name, "file_info") && after[rootOffsets[i]] == 33) {
			file_info = after + rootOffsets[i] + 1;
		}
		free(to_free);
	}
	if (file_info) {
		FILE *alldata = fopen("alldata.bin", "rb");
		if (!alldata) {
			fputs("Failed to open alldata.bin", stderr);
			retval = 1;
			goto cleanup;
		}
		int64_t num_files;
		int64_t *fileKeyIndices = parse_array(file_info, size - (file_info - buffer), &num_files, &after);
		int64_t *fileOffsets = parse_array(after, size - (after - buffer), &num_els, &after);
		if (num_els != num_files) {
			fprintf(stderr, "Object key index array %" PRId64 " entries, but offfset array has %" PRId64 " entries\n", num_files, num_els);
			retval = 1;
			fclose(alldata);
			goto cleanup;
		}
		puts("file_info:");
		for (int64_t i = 0; i < num_files; i++)
		{
			char name_buf[128];
			char *to_free;
			char *name = key_name(&keys, fileKeyIndices[i], &to_free, name_buf, sizeof(name_buf));
			printf("\t%s - offset: %" PRId64 ", type: %d", name, fileOffsets[i], after[fileOffsets[i]]);
			if (after[fileOffsets[i]] == 32) {
				uint8_t *after_arr;
				int64_t num_arr;
				int64_t *arrOffsets = parse_array(after + fileOffsets[i] + 1, size - (after - buffer) - fileOffsets[i] - 1, &num_arr, &after_arr);
				if (num_arr >= 2) {
					uint8_t *trash;
					int64_t file_offset = parse_int(after_arr + arrOffsets[0], size - (after_arr + arrOffsets[0] - buffer), &trash);
					int64_t file_size = parse_int(after_arr + arrOffsets[1], size - (after_arr + arrOffsets[1] - buffer), &trash);
					printf(" - File Offset %" PRId64 ", File Size %" PRId64, file_offset, file_size);
					if (file_offset > 0 && file_size > 0) {
						size_t pre_size = strlen("unpacked/");
						size_t post_size = strlen(name);
						char * out_name = malloc(pre_size + post_size + 1);
						memcpy(out_name, "unpacked/", pre_size);
						memcpy(out_name + pre_size, name, post_size + 1);
						FILE *out = fopen(out_name, "wb");
						if (!out) {
							printf("Failed to open %s\n", out_name);
						}
						free(out_name);
						if (out) {
							fseek(alldata, file_offset, SEEK_SET);
							uint8_t *b = malloc(file_size);
							size_t bytes = fread(b, 1, file_size, alldata);
							fwrite(b, 1, bytes, out);
							fclose(out);
						}
					}
				}
				free(arrOffsets);
			}
			putchar('\n');
			free(to_free);
		}
		fclose(alldata);
	}
cleanup:
	fclose(f);
	free(buffer);
	return retval;
}
