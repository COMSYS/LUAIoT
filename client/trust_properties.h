/**
 * @file trust_properties.h
 * @author COMSYS, RWTH Aachen University
 * @brief Header file for managing certificate trust properties
 * @version 0.1
 * @date 2024-11-01
 */

#ifndef _TRUST_PROPERTIES_H
#define _TRUST_PROPERTIES_H

/**
 * @brief Structure that holds the personal information the CA should insert into the certificate
 *
 */
struct TrustProperties
{
    int identifierOfProperty;
    char *propertyValue;
    size_t valueLength;
};

/**
 * @brief Validates trust property values
 * @param prop Pointer to trust property structure
 * @return bool true if valid, false otherwise
 */
bool isValidTrustProperty(const struct TrustProperties *prop);

/**
 * @brief Creates a new trust property
 * @param id Property identifier
 * @param value Property value string
 * @return struct TrustProperties* New property or NULL if error
 */
struct TrustProperties* createTrustProperty(int id, const char *value);

/**
 * @brief Frees a trust property
 * @param prop Property to free
 */
void freeTrustProperty(struct TrustProperties *prop);

#endif
