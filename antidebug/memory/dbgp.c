#include "dbgp.h"

static inline void sig_to_str(DWORD sig, char out[5]) {
    out[0] = (char)(sig & 0xFF);
    out[1] = (char)((sig >> 8) & 0xFF);
    out[2] = (char)((sig >> 16) & 0xFF);
    out[3] = (char)((sig >> 24) & 0xFF);
    out[4] = '\0';
}

// simple byte search (like memmem), returns pointer to first match or NULL
static inline const unsigned char* find_bytes(const unsigned char* hay, size_t haylen,
    const unsigned char* needle, size_t needlelen)
{
    if (!hay || !needle) return NULL;
    if (needlelen == 0) return hay;
    if (haylen < needlelen) return NULL;

    size_t max = haylen - needlelen;
    for (size_t i = 0; i <= max; ++i) {
        if (hay[i] == needle[0]) {
            size_t j;
            for (j = 1; j < needlelen; ++j) {
                if (hay[i + j] != needle[j]) break;
            }
            if (j == needlelen) return hay + i;
        }
    }
    return NULL;
}

// too lazy to syscall this
bool dbgp() 
{
    const DWORD provider = 'ACPI';
    const DWORD enumSize = EnumSystemFirmwareTables(provider, NULL, 0);
    if (enumSize == 0) {
        return false;
    }

    unsigned char* enumBuf = (unsigned char*)malloc(enumSize);
    if (!enumBuf) {
        return false;
    }

    const DWORD returned = EnumSystemFirmwareTables(provider, enumBuf, enumSize);
    if (returned == 0 || returned > enumSize) {
        free(enumBuf);
        return false;
    }

    const unsigned char needle[] = "DBGP";
    const size_t needlelen = sizeof(needle) - 1;

    const size_t nTables = returned / 4;
    for (size_t i = 0; i < nTables; ++i) {
        const DWORD tableId = ((DWORD)enumBuf[i * 4]) |
            ((DWORD)enumBuf[i * 4 + 1] << 8) |
            ((DWORD)enumBuf[i * 4 + 2] << 16) |
            ((DWORD)enumBuf[i * 4 + 3] << 24);

        char sig[5];
        sig_to_str(tableId, sig);

        if (sig[0] == 'D' && sig[3] == 'P') {
            continue;
        }

        const UINT sizeNeeded = GetSystemFirmwareTable(provider, tableId, NULL, 0);
        if (sizeNeeded == 0) {
            continue;
        }

        unsigned char* tblBuf = (unsigned char*)malloc(sizeNeeded);
        if (!tblBuf) {
            continue;
        }

        const UINT got = GetSystemFirmwareTable(provider, tableId, tblBuf, sizeNeeded);
        if (got == 0 || got > sizeNeeded) {
            free(tblBuf);
            continue;
        }

        const unsigned char* match = find_bytes(tblBuf, got, needle, needlelen);
        if (match) {
            return true;
        }

        free(tblBuf);
    }

    free(enumBuf);
    return false;
}
