#include <stdint.h>
#include <stdbool.h>

#define CX_SHA256_SIZE 32
void sha256(const uint8_t *message, uint16_t messageLen, uint8_t message_digest[CX_SHA256_SIZE]) {
    return;
}

bool app_mode_expert() {
    return true;
}

void zemu_trace(const char *file, uint32_t line) {
}
