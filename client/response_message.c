/**
 * @file response_message.c
 * @author COMSYS, RWTH Aachen University
 * @brief
 * @version 0.1
 * @date 2024-11-01
 */

#include "response_message.h"
#include "encoding/base64.h"
#include "pkix/x509_cert_parse.h"
#include <stdint.h>

enum ASC handleEnrollmentResponse(struct AuthenticationStruct *authStr, char *messageContent)
{
    // check if message code could be present
    if (strlen(messageContent) < 12)
    {
        return malformedResponse;
    }
    // get the return code of the http request
    char *returnCode = malloc(4 * sizeof(char));
    strncpy(returnCode, messageContent + 9, 3);
    returnCode[3] = '\0';


    int returnCodeInt = 0;
    returnCodeInt = atoi(returnCode);
    free(returnCode);

    switch (returnCodeInt)
    {
    case 200:
    {
        // everything okay go on with processing
        // check if content type header is present and correct
        char *lengthUntilContentTypeHeader = strstr(messageContent, "Content-Type");
        if (lengthUntilContentTypeHeader == NULL)
        {
            return malformedResponse;
        }

        // check content type header structure
        if (strncmp("Content-Type: text/plain", lengthUntilContentTypeHeader, LENGTH_OF_CONTENT_TYPE_HEADER) != 0)
        {
            return malformedResponse;
        }

        // check if content length header is present and correct
        char *lengthUntilContentLengthHeader = strstr(messageContent, CONTENT_LENGTH_HEADER);
        if (lengthUntilContentLengthHeader == NULL)
        {
            return malformedResponse;
        }

        // check content type header structure
        if (strncmp(CONTENT_LENGTH_HEADER, lengthUntilContentLengthHeader, LENGTH_OF_CONTENT_LENGTH_HEADER) != 0)
        {
            return malformedResponse;
        }

        // go to begin of content length header
        messageContent = lengthUntilContentLengthHeader;

        // get the content length and check it
        int lengthUntilContentLengthHeaderEnd = strcspn(messageContent, "\r\n");
        char *contentLength = malloc((lengthUntilContentLengthHeaderEnd - LENGTH_OF_CONTENT_LENGTH_HEADER + 1) * sizeof(char));
        strncpy(contentLength, &messageContent[LENGTH_OF_CONTENT_LENGTH_HEADER], lengthUntilContentLengthHeaderEnd - LENGTH_OF_CONTENT_LENGTH_HEADER);
        contentLength[lengthUntilContentLengthHeaderEnd - LENGTH_OF_CONTENT_LENGTH_HEADER] = '\0';
        int contentLengthInt = 0;
        contentLengthInt = atoi(contentLength);
        if (contentLengthInt == 0)
        {
            free(contentLength);
            return malformedResponse;
        }

        // jump to the begin of the certificateChain
        char *lengthUntilCertificateChain = strstr(messageContent, "\r\n\r\n");

        messageContent = lengthUntilCertificateChain + 4 * sizeof(char);

        // check if that content length equals length of content
        if (strlen(messageContent) != contentLengthInt)
        {
            free(contentLength);
            return malformedResponse;
        }

        uint8_t *dec = malloc(1024);
        size_t actual_decoded_length = 0;

        base64Decode(messageContent, strlen(messageContent), dec, &actual_decoded_length);
        

        int start = 0;
        size_t length = 0;
        for (int i = start; i < actual_decoded_length; i++) {
            if (
                    dec[i] == 0x30 &&
                    dec[i + 1] == 0x82 &&
                    dec[i + 4] == 0x30 &&
                    dec[i + 5]
                    ) {
                start = i;
                length = dec[i + 2] * 0x100 + dec[i + 3];

                break;
            }
        }

        char_t *output = malloc(1024);
        size_t outputLen = 0;

        // Why a +4? No clue. But it doesn't work with an offset of less than 4
        base64Encode(dec + start, length+4, output, &outputLen);
 
        X509CertInfo *certInfo = tlsAllocMem(sizeof(X509CertInfo));

        error_t error = x509ParseCertificate(dec + start, length+4, certInfo);

        if (error) {
            return malformedResponse;
        }

        // allocate memory for the certificate and copy certificate chain
        authStr->certificate = malloc((length + 4) * sizeof(char));
        
        strncpy((char *) authStr->certificate, (char *) dec + start, length + 4);
        //authStr->certificate[length] = '\0';
        free(contentLength);
        return actionSuccessful;
        break;
    }

    case 600:
        return malformedRequest;
        break;

    case 601:
        return malformedIdentifier;
        break;

    case 602:
        return identifierOnRevocationList;
        break;

    case 603:
        return accountDoesNotExist;
        break;

    case 604:
        return malformedPublicKey;
        break;

    case 605:
        return serverInternal;
        break;

    default:
        return malformedResponse;
        break;
    }
}
