/**
 * @file authentication_scheme_codes.h
 * @author COMSYS, RWTH Aachen University
 * @brief Header file for authentication scheme return codes.
 * @version 0.1
 * @date 2024-11-01
 */

#ifndef _AUTHENTICATION_SCHEME_CODES
#define _AUTHENTICATION_SCHEME_CODES

#include <stdbool.h>

/**
 * @brief The return codes of the authentication scheme.
 */
enum ASC
{
    // Successful actions
    actionSuccessful,            /**< Action was successful */
    registrationSuccessful,      /**< Registration was successful */
    certificationSuccessful,     /**< Certification was successful */
    authenticationSuccessful,    /**< Authentication was successful */
    revocationSuccessful,        /**< Revocation was successful */

    // Return codes from the server to the end device
    malformedRequest,            /**< Malformed request */
    malformedIdentifier,         /**< Malformed identifier */
    malformedPublicKey,          /**< Malformed public key */
    accountDoesNotExist,         /**< Account does not exist */
    identifierOnRevocationList,  /**< Identifier is on the revocation list */
    serverInternal,              /**< Server internal error */

    // Return codes from the server to the user
    accountAlreadyExists,        /**< Account already exists */
    invalidContact,              /**< Invalid contact information */
    badRevocationReason,         /**< Bad revocation reason */
    unregisteredUser,            /**< Unregistered user */

    // Internal errors
    unInitialized,               /**< Uninitialized struct */
    invalidState,                /**< Invalid state */
    tooManyRetries,              /**< Too many retries */
    malformedPrivateKey,         /**< Malformed private key */
    malformedResponse,           /**< Malformed response */
    malformedTrustProperties,    /**< Malformed trust properties */
    reallocationFailed,          /**< Reallocation failed */
    missingNecessaryROT,         /**< Missing necessary ROT */
    missingOptionalROT,          /**< Missing optional ROT */

    // Connection errors
    CaUnreachable,               /**< CA is unreachable */
    TlsConnectionFailure,        /**< TLS connection failure */
    errorDuringReceiving,        /**< Error during receiving */
    errorDuringSending,          /**< Error during sending */
    malformedCaIdentifier,       /**< Malformed CA identifier */

    // Authentication and certificate check
    invalidCaCerts,              /**< Invalid CA certificates */
    invalidEndDeviceCertificate, /**< Invalid end device certificate */
    certificateDoesNotIncludeIdentifier, /**< Certificate does not include identifier */
    expiredCertificate,          /**< Expired certificate */
    revokedCertificate,          /**< Revoked certificate */
};

/**
 * @brief Checks if ASC code indicates success
 * @param code The ASC code to check
 * @return bool true if successful, false otherwise
 */
static inline bool isASCSuccess(enum ASC code) {
    return code <= revocationSuccessful;
}

#endif
