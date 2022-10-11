/*
 * Copyright (c) 2011-2012 by ps3dev.net
 * This file is released under the GPLv2.
 */

#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include "types.h"

void _hexdump(FILE *fp, const char *name, u32 offset, u8 *buf, int len, BOOL print_addr) {
    int i, j, align = strlen(name) + 1;

    fprintf(fp, "%s ", name);
    if (print_addr == TRUE)
        fprintf(fp, "%08x: ", offset);
    for (i = 0; i < len; i++) {
        if (i % 16 == 0 && i != 0) {
            fprintf(fp, "\n");
            for (j = 0; j < align; j++)
                putchar(' ');
            if (print_addr == TRUE)
                fprintf(fp, "%08X: ", offset + i);
        }
        fprintf(fp, "%02X ", buf[i]);
    }
    fprintf(fp, "\n");
}

u8 *_read_buffer(s8 *file, u32 *length) {
    FILE *fp;
    u32 size;

    if ((fp = fopen(file, "rb")) == NULL)
        return NULL;

    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    u8 *buffer = (u8 *) malloc(sizeof (u8) * size);
    fread(buffer, sizeof (u8), size, fp);

    if (length != NULL)
        *length = size;

    fclose(fp);

    return buffer;
}

void _write_buffer(s8 *file, u8 *buffer, u32 length) {
    FILE *fp;

    if ((fp = fopen(file, "wb")) == NULL)
        return;

    fwrite(buffer, sizeof (u8), length, fp);
    fclose(fp);
}
