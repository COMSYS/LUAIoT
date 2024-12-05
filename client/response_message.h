/**
 * @file response_message.h
 * @author COMSYS, RWTH Aachen University
 * @brief
 * @version 0.1
 * @date 2024-11-01
 */

#ifndef _RESPONSE_MESSAGE_H
#define _RESPONSE_MESSAGE_H

#include <string.h>
#include <stdlib.h>

#include "authentication_scheme_codes.h"
#include "authentication_struct.h"
#include "defines.h"

/**
 * @brief Function that handles the enrollment request and performs actions based on the HTTP response code
 *
 * @param authStr Pointer to the authentication struct
 * @param messageContent The received message.
 * @return ASC code that represents the function outcome
 */
enum ASC handleEnrollmentResponse(struct AuthenticationStruct *authStr, char *messageContent);

#endif
