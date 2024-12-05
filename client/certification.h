/**
 * @file certification.h
 * @author COMSYS, RWTH Aachen University
 * @brief Header file for handling the certification process of end devices.
 * @version 0.1
 * @date 2024-11-01
 */

#ifndef _CERTIFICATION_H
#define _CERTIFICATION_H

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <sys/time.h>
#include "authentication_struct.h"
#include "identifier.h"
#include "authentication_scheme_codes.h"
#include "trust_properties.h"
#include "response_message.h"

/**
 * @brief Creates an instance of the authentication struct.
 * 
 * @param authStr Pointer to the authentication struct to initialize.
 * @param publicKey Pointer to the public key buffer.
 * @param publicKeySize Size of the public key in bytes.
 * @param send Function pointer for sending data to CA.
 * @param receive Function pointer for receiving data from CA.
 * @param numberOfRetries Maximum number of retry attempts.
 * @param checkCertificate Flag to enable certificate validation.
 * @param tlsContext Pointer to TLS context for secure communication.
 * @return ASC Status code indicating success or failure.
 */
enum ASC createAuthenticationStruct(
    struct AuthenticationStruct *authStr,
    const char *publicKey,
    uint16_t publicKeySize,
    sendDataCA send,
    receiveDataCA receive,
    uint8_t numberOfRetries,
    bool checkCertificate,
    TlsContext *tlsContext
);

/**
 * @brief Frees the allocated memory of the different components.
 * 
 * @param authStr Pointer to the authentication struct.
 * @return enum ASC Code that represents the function outcome.
 */
enum ASC freeAuthenticationStruct(struct AuthenticationStruct *authStr);

/**
 * @brief Sets the state of the authentication struct.
 * 
 * @param authStr Pointer to the authentication struct.
 * @param previousActionSuccessful Outcome of the previous action.
 * @return enum ASC Code that represents the function outcome.
 */
enum ASC setState(struct AuthenticationStruct *authStr, bool previousActionSuccessful);

/**
 * @brief Performs the certification of the end device.
 * 
 * @param authStr Pointer to the authentication struct.
 * @return enum ASC Code that represents the function outcome.
 */
enum ASC handleCertification(struct AuthenticationStruct *authStr);

/**
 * @brief Handles the creation of the request and sending it to the CA.
 * 
 * @param authStr Pointer to the authentication struct.
 * @return enum ASC Code that represents the function outcome.
 */
enum ASC handleRequest(struct AuthenticationStruct *authStr);

/**
 * @brief Handles the response from the CA.
 * 
 * @param authStr Pointer to the authentication struct.
 * @return enum ASC Code that represents the function outcome.
 */
enum ASC handleResponse(struct AuthenticationStruct *authStr);

/**
 * @brief Checks the received certificate from the CA.
 * 
 * @param authStr Pointer to the authentication struct.
 * @return enum ASC Code that represents the function outcome.
 */
enum ASC checkCertificate(struct AuthenticationStruct *authStr);

/**
 * @brief Validates a certificate chain
 * @param cert Certificate to validate
 * @param chainLength Length of certificate chain
 * @param trustAnchors Trust anchors for validation
 * @return enum ASC Status code
 */
static bool validateCertificateChain(const unsigned char *cert);

/**
 * @brief Checks certificate expiration
 * @param cert Certificate to check
 * @return bool Status code
 */
static bool checkCertificateExpiration(const unsigned char *cert);

/**
 * @brief Checks certificate format
 * @param cert Certificate to check
 * @return bool Status code
 */
static bool validateCertificateFormat(const unsigned char *cert);

/**
 * @brief Resets the certification (state and numberOfFailedTries).
 * 
 * @param authStr Pointer to the authentication struct.
 * @return bool Code that represents the function outcome.
 */
enum ASC resetCertification(struct AuthenticationStruct *authStr);

#endif
