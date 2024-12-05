/**
 * @file certification.c
 * @author COMSYS, RWTH Aachen University
 * @brief Implementation of certification process functions
 * @version 0.1
 * @date 2024-11-01
 */

#include "certification.h"
#include "tls.h"
#include <stdio.h>

enum ASC createAuthenticationStruct(
    struct AuthenticationStruct *authStr,
    const char *publicKey,
    uint16_t publicKeySize,
    sendDataCA send,
    receiveDataCA receive,
    uint8_t numberOfRetries,
    bool checkCertificate,
    TlsContext *tlsContext)
{
    if (!authStr || !publicKey || !send || !receive || !tlsContext) {
        return unInitialized;
    }

    // Initialize with safe defaults
    memset(authStr, 0, sizeof(struct AuthenticationStruct));
    authStr->state = SendingEnrollmentRequest;

    // Validate public key
    if (strlen(publicKey) != publicKeySize) {
        return malformedPublicKey;
    }

    // Allocate and copy public key
    authStr->publicKey = malloc((publicKeySize + 1) * sizeof(char));
    if (!authStr->publicKey) {
        return reallocationFailed;
    }

    memcpy(authStr->publicKey, publicKey, publicKeySize);
    authStr->publicKey[publicKeySize] = '\0';
    
    // Initialize remaining fields
    authStr->publicKeySize = publicKeySize;
    authStr->checkCertificate = checkCertificate;
    authStr->send = send;
    authStr->receive = receive;
    authStr->numberOfRetries = numberOfRetries;
    authStr->tlsContext = tlsContext;
    authStr->initialized = true;

    return actionSuccessful;
}

enum ASC freeAuthenticationStruct(struct AuthenticationStruct *authStr)
{
    // check if struct is initialized
    if (!authStr->initialized)
    {
        return unInitialized;
    }

    // free the identifier and public key 
    free(authStr->publicKey);

    // free the certificate
    if (authStr->state == CertificationFinished || authStr->certificate != NULL)
    {
        free(authStr->certificate);
    }
    return actionSuccessful;
}

enum ASC setState(struct AuthenticationStruct *authStr, bool actionSuccessful)
{
    if (!authStr || !authStr->initialized) {
        return unInitialized;
    }

    if (actionSuccessful) {
        switch (authStr->state) {
            case SendingEnrollmentRequest:
                authStr->state = WaitingForCertificate;
                break;
            case WaitingForCertificate:
                authStr->state = CertificateReceived;
                break;
            case CertificateReceived:
                authStr->state = CertificationFinished;
                break;
            case CertificationFinished:
                return invalidState;
            default:
                return invalidState;
        }
    } else {
        authStr->numberOfFailedTries++;
        if (authStr->state != SendingEnrollmentRequest) {
            authStr->state = SendingEnrollmentRequest;
        }
    }

    return actionSuccessful;
}

enum ASC handleCertification(struct AuthenticationStruct *authStr)
{
    if (!authStr || !authStr->initialized) {
        return unInitialized;
    }

    enum ASC retCode = actionSuccessful;
    bool stateChanged;

    while (true) {
        // Check retry limit for all states except CertificationFinished
        if (authStr->state != CertificationFinished && 
            authStr->numberOfFailedTries > authStr->numberOfRetries) {
            return tooManyRetries;
        }

        stateChanged = false;
        switch (authStr->state) {
            case SendingEnrollmentRequest:
                retCode = handleRequest(authStr);
                stateChanged = (retCode == actionSuccessful);
                break;

            case WaitingForCertificate:
                retCode = handleResponse(authStr);
                stateChanged = (retCode == actionSuccessful);
                break;

            case CertificateReceived:
                if (!authStr->checkCertificate) {
                    stateChanged = true;
                    retCode = actionSuccessful;
                } else {
                    retCode = checkCertificate(authStr);
                    if (retCode != actionSuccessful) {
                        return retCode;
                    }
                    stateChanged = true;
                }
                break;

            case CertificationFinished:
                return certificationSuccessful;

            default:
                return invalidState;
        }

        if (!stateChanged) {
            setState(authStr, false);
            if (retCode != actionSuccessful) {
                return retCode;
            }
        } else {
            setState(authStr, true);
        }
    }
}

enum ASC handleRequest(struct AuthenticationStruct *authStr)
{
    if (!authStr || !authStr->initialized || !authStr->publicKey) {
        return unInitialized;
    }

    if (authStr->state != SendingEnrollmentRequest) {
        return invalidState;
    }

    static const char requestTemplate[] = 
        "POST /.well-known/est/simpleenroll HTTP/1.1\r\n"
        "Content-Type: application/pkcs10\r\n"
        "Content-Length: %d\r\n"
        "%s\r\n";

    size_t bufferSize = strlen(requestTemplate) + 
                       SERIALIZED_ENR_REQ_OBJ_STRING + 
                       authStr->publicKeySize + 3;
    
    char *sendBuffer = malloc(bufferSize);
    if (!sendBuffer) {
        return reallocationFailed;
    }

    int written = -1;
    int sendBufferLength = snprintf(sendBuffer, bufferSize, 
                                  requestTemplate,
                                  authStr->publicKeySize + 1, 
                                  authStr->publicKey);

    if (sendBufferLength < 0 || sendBufferLength >= bufferSize) {
        free(sendBuffer);
        return errorDuringSending;
    }

    authStr->send(sendBuffer, sendBufferLength + 1, &written);

    free(sendBuffer);

    if (written == -1) {
        return CaUnreachable;
    }
    
    return (written == sendBufferLength + 1) ? 
           actionSuccessful : errorDuringSending;
}

enum ASC handleResponse(struct AuthenticationStruct *authStr)
{
    if (!authStr || !authStr->initialized || !authStr->tlsContext) {
        return unInitialized;
    }

    if (authStr->state != WaitingForCertificate) {
        return invalidState;
    }

    enum ASC ASCReturnCode = actionSuccessful;
    char *receiveBuffer = malloc(RECEIVE_BUFFER_SIZE + 1);
    if (!receiveBuffer) {
        return reallocationFailed;
    }

    size_t bytesRead = 1;
    size_t totalLength = 0;
    error_t err = 0;

    while (bytesRead > 0 || ASCReturnCode == malformedResponse) {
        if (totalLength >= RECEIVE_BUFFER_SIZE) {
            free(receiveBuffer);
            return errorDuringReceiving;
        }

        err = tlsRead(authStr->tlsContext, 
                     receiveBuffer + totalLength,
                     RECEIVE_BUFFER_SIZE - totalLength, 
                     &bytesRead, 
                     0);
        
        if (err == ERROR_WOULD_BLOCK) {
            continue;
        } else if (err != 0) {
            free(receiveBuffer);
            return TlsConnectionFailure;
        }

        totalLength += bytesRead;
        receiveBuffer[totalLength] = '\0';
        
        ASCReturnCode = handleEnrollmentResponse(authStr, receiveBuffer);
    }

    free(receiveBuffer);
    return ASCReturnCode;
}

enum ASC checkCertificate(struct AuthenticationStruct *authStr)
{
    if (!authStr || !authStr->initialized) {
        return unInitialized;
    }

    if (!authStr->certificate) {
        return invalidEndDeviceCertificate;
    }

    if (authStr->state != CertificateReceived) {
        return invalidState;
    }

    // Basic certificate validation checks
    if (!validateCertificateFormat(authStr->certificate)) {
        return invalidEndDeviceCertificate;
    }

    if (checkCertificateExpiration(authStr->certificate)) {
        return expiredCertificate;
    }

    if (!validateCertificateChain(authStr->certificate)) {
        return invalidCaCerts;
    }

    return actionSuccessful;
}

static bool validateCertificateChain(const unsigned char *cert)
{
    if (!cert)
    {
        return false;
    }

    // TODO: Implement chain validation using TLS context trust anchors
    // Placeholder for actual implementation
    return true;
}

static bool checkCertificateExpiration(const unsigned char *cert)
{
    if (!cert)
    {
        return true;
    }

    // TODO: Parse ASN.1 dates and compare with current time
    // Placeholder implementation
    return false;
}

// Helper function declarations (to be implemented)
static bool validateCertificateFormat(const unsigned char *cert)
{
    if (!cert) {
        return false;
    }

    // Basic ASN.1 structure validation
    // TODO: Implement full X.509 validation
    return (cert[0] == 0x30);  // Check for ASN.1 sequence
}

enum ASC resetCertification(struct AuthenticationStruct *authStr)
{
    if (!authStr || !authStr->initialized) {
        return unInitialized;
    }

    if (authStr->state == CertificationFinished) {
        // Free certificate if it exists
        if (authStr->certificate) {
            free(authStr->certificate);
            authStr->certificate = NULL;
        }
    }

    authStr->state = SendingEnrollmentRequest;
    authStr->numberOfFailedTries = 0;
    
    return actionSuccessful;
}
