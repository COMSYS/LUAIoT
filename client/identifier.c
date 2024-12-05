/**
 * @file identifier.c
 * @author COMSYS, RWTH Aachen University
 * @brief Implementation of identifier handling functions
 * @version 0.1
 * @date 2024-11-01
 */

#include "identifier.h"

bool checkIdentifierFormat(const char *identifier)
{
    if (!identifier) {
        return false;
    }

    size_t len = strlen(identifier);
    if (len != IDENTIFIER_SIZE) {
        return false;
    }

    // Check separator positions
    if (identifier[ORG_IDENTIFIER_SIZE] != ':' || 
        identifier[ORG_IDENTIFIER_SIZE + USER_IDENTIFIER_SIZE + 1] != ':') {
        return false;
    }

    // Count separators
    int separators = 0;
    for (size_t i = 0; i < len; i++) {
        if (identifier[i] == ':') {
            separators++;
        }
    }

    return separators == 2;
}

void serializeIdentifier(char *buffer, const char *org, const char *user, const char *device)
{
    if (!buffer || !org || !user || !device) {
        return;
    }

    // Clear buffer first
    memset(buffer, 0, IDENTIFIER_SIZE + 1);
    
    // Copy components with proper separators
    strncpy(buffer, org, ORG_IDENTIFIER_SIZE);
    buffer[ORG_IDENTIFIER_SIZE] = ':';
    strncpy(buffer + ORG_IDENTIFIER_SIZE + 1, user, USER_IDENTIFIER_SIZE);
    buffer[ORG_IDENTIFIER_SIZE + USER_IDENTIFIER_SIZE + 1] = ':';
    strncpy(buffer + ORG_IDENTIFIER_SIZE + USER_IDENTIFIER_SIZE + 2, device, DEVICE_IDENTIFIER_SIZE);
    buffer[IDENTIFIER_SIZE] = '\0';
}
