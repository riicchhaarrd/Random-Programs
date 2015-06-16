#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#define OUT_TO_FILE

#ifdef OUT_TO_FILE
FILE *out_file = NULL;
#endif // OUT_TO_FILE

int print_out(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    #ifdef OUT_TO_FILE
    vfprintf(out_file, format, args);
    #else
    vprintf(format, args);
    #endif // OUT_TO_FILE

    va_end(args);
}

typedef struct {
    int inuse;
    int offset;
    BYTE v1, v2;
} UNEQ;

int main(int argc, char **argv) {
    //let's assume argv[1] = the original?
	if(argc < 3) {
        printf("Usage: %s original.exe modified.exe\n", argv[0]);
		return 0;
	}
    #ifdef OUT_TO_FILE
    if( ( out_file = fopen("out_file.txt", "w") ) == NULL)
        return 0;
    #endif // OUT_TO_FILE
    int i;
    for(i = 0; i < argc; i++)
        printf("%d: %s\n", i, argv[i]);

    HANDLE hFile1 = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if(hFile1 == INVALID_HANDLE_VALUE)
        return 0;

    HANDLE hFile2 = CreateFileA(argv[2], GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if(hFile2 == INVALID_HANDLE_VALUE)
        return 0;

    DWORD dwFileSize = 0;

    if(( dwFileSize = GetFileSize(hFile1, 0) ) != GetFileSize(hFile2, 0)) {
        printf("unequal filesize\n");
        CloseHandle(hFile1);
        CloseHandle(hFile2);
        return 0;
    } else
    printf("filesize = %lu\n", dwFileSize);

    BYTE *buf = NULL, *buf2 = NULL;

    buf = (BYTE*)malloc(dwFileSize);
    buf2 = (BYTE*)malloc(dwFileSize);

    DWORD dwSizeRead = 0;

    ReadFile(hFile1, buf, dwFileSize, &dwSizeRead, NULL);
    ReadFile(hFile2, buf2, dwFileSize, &dwSizeRead, NULL);

#if 0
    if(!memcmp(buf,buf2,dwFileSize))
        printf("equal\n");
    else
        printf("not equal\n");
#endif


    #define BASE_SIZE ( ( dwFileSize > 1024 ) ? 1024 : dwFileSize )
    UNEQ *idx = (UNEQ*)malloc( sizeof(UNEQ) * BASE_SIZE ), *q_tmp = NULL;
    int uneq_cur = 0, uneq_size = BASE_SIZE;

    int in_block = 0, c_blocks = 0;

    for(i = 0; i < dwFileSize; i++) {
        if(buf[i] != buf2[i]) {
            if(!in_block) {
                int pattern_size = (dwFileSize - i) < 10 ? (dwFileSize - i) : 10;
                print_out("\n%02X at %d (0x%02X) (orig: %02X => modif: %02X) Pattern: { ", buf[i], i, i, buf[i], buf2[i]);
                int k;
                for(k=0;k<pattern_size;k++)
                    print_out("%02X ", buf[i + k]);
                print_out("}\n");
                c_blocks++;
            }
            in_block++;
            //printf("%d: %02X != %02X\n", i, *(buf+i), *(buf2+i));
            if(uneq_cur >= uneq_size) {
                q_tmp = (UNEQ*)realloc(idx, sizeof(UNEQ) * (BASE_SIZE + uneq_size));
                if(q_tmp == NULL) {
                    printf("failed to alloc mem\n");
                    break;
                }
                idx = q_tmp;
                q_tmp = NULL;
                uneq_size += BASE_SIZE;
            }
            UNEQ q;
            q.inuse = TRUE;
            q.offset = i;
            q.v1 = *(buf+i);
            q.v2 = *(buf2+i);
            idx[uneq_cur++] = q;
        } else {
            //print_out("%02X ", buf[i]);
        }

    }

    if(!memcmp(buf,buf2,dwFileSize))
        printf("Buffers are equal\n");
    else printf("Buffers are unequal\n");
    printf("different block count: %d\n", c_blocks);
    printf("uneq size = %d\n", uneq_size);

    free(idx);

    free(buf);
    free(buf2);
    CloseHandle(hFile1);
    CloseHandle(hFile2);
    #ifdef OUT_TO_FILE
    fclose(out_file);
    #endif // OUT_TO_FILE
    //getchar();
	return 0;
}
