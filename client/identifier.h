/**
 * @file identifier.h
 * @author COMSYS, RWTH Aachen University
 * @brief Header file for handling end device identifiers
 * @version 0.1
 * @date 2024-11-01
 */

#ifndef _IDENTIFIER_H
#define _IDENTIFIER_H

#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include "defines.h"

/**
 * @brief Structure that holds the identifier of an end device.
 */
struct End_device_identifier
{
    char organization_identifier[ORG_IDENTIFIER_SIZE]; /**< Organization identifier */
    char user_identifier[USER_IDENTIFIER_SIZE];        /**< User identifier */
    char device_identifier[DEVICE_IDENTIFIER_SIZE];    /**< Device identifier */
};

/**
 * @brief Checks the format of an identifier string.
 * 
 * @param identifier The identifier string to be checked.
 * @return true if the identifier format is correct.
 * @return false if the identifier format is incorrect.
 */
bool checkIdentifierFormat(const char *identifier);

/**
 * @brief Concatenates the different parts into an identifier string.
 * 
 * @param buffer Buffer where the identifier should be stored.
 * @param org Part that identifies the organization that owns the device.
 * @param user Part that identifies the user that registered the device.
 * @param device Part that identifies the end device.
 */
void serializeIdentifier(
    char *buffer,
    const char *org,
    const char *user,
    const char *device
);

#endif
