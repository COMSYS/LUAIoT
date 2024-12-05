/**
 * @file authentication_struct.h
 * @author COMSYS, RWTH Aachen University
 * @brief Header file for the authentication struct and related enums.
 * @version 0.1
 * @date 2024-11-01
 */

#ifndef _AUTHENTICATION_STRUCT_H
#define _AUTHENTICATION_STRUCT_H

#include <stdbool.h>
#include "callbacks.h"
#include "tls.h"

/**
 * @brief Enum that identifies what part was evaluated.
 */
enum EvaluationIdentifier
{
    HandleCertification = 0, /**< Handle certification process */
    KeyCreation = 1,         /**< Key creation process */
    CreatingEnrollmentRequest = 2, /**< Creating enrollment request */
    LatencyBetweenRequestResponse = 3, /**< Latency between request and response */
    HandleEnrollmentResponse = 4, /**< Handle enrollment response */
};

/**
 * @brief Enum that describes the current state of the authentication process.
 */
enum AuthenticationState
{
    SendingEnrollmentRequest, /**< Sending enrollment request */
    WaitingForCertificate,    /**< Waiting for certificate */
    CertificateReceived,      /**< Certificate received */
    CertificationFinished,    /**< Certification finished */
};

/**
 * @brief Structure that holds everything necessary for the authentication of an end device.
 */
struct AuthenticationStruct
{
    enum AuthenticationState state; /**< Current state of the struct */
    bool initialized;               /**< Indicates whether the struct is initialized */
    char *identifier;               /**< Assigned device identifier */
    uint16_t publicKeySize;         /**< Size of the public key */
    char *publicKey;                /**< Public key for the new certificate */
    sendDataCA send;                /**< Callback to send data to the CA */
    receiveDataCA receive;          /**< Callback to receive data from the CA */
    sendMeasuredData sendMeasuredData; /**< Callback to send measurements to an evaluation server */
    bool sendMeasured;              /**< Indicates whether evaluation data should be sent */
    uint8_t numberOfRetries;        /**< Number of retries before closing the connection */
    uint8_t numberOfFailedTries;    /**< Number of current failed attempts */
    bool checkCertificate;          /**< Indicates whether the certificate should be checked */
    unsigned char *certificate;     /**< Received certificate */
    TlsContext *tlsContext;         /**< TLS context */
};

/**
 * @brief Safely deallocates all dynamic memory in the authentication struct
 * @param auth Pointer to the authentication struct
 */
void cleanupAuthenticationStruct(struct AuthenticationStruct *auth);

/**
 * @brief Deep copies an authentication struct
 * @param dest Destination struct
 * @param src Source struct
 * @return enum ASC Status code
 */
enum ASC copyAuthenticationStruct(struct AuthenticationStruct *dest, 
                                const struct AuthenticationStruct *src);

/**
 * @brief Checks if authentication struct is in a valid state
 * @param auth Pointer to the authentication struct
 * @return bool true if valid, false otherwise
 */
static inline bool isValidAuthenticationStruct(const struct AuthenticationStruct *auth) {
    return auth && auth->initialized && 
           auth->publicKey && auth->publicKeySize > 0 &&
           auth->send && auth->receive && auth->tlsContext;
}

/**
 * @brief Gets string representation of authentication state
 * @param state Authentication state to convert
 * @return const char* String representation
 */
const char* getAuthenticationStateString(enum AuthenticationState state);

#endif
