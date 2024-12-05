/**
 * @file defines.h
 * @author COMSYS, RWTH Aachen University
 * @brief Global constants and configuration parameters
 * @version 0.1
 * @date 2024-11-01
 */
#ifndef _DEFINES_H
#define _DEFINES_H

// define the buffer size
#define RECEIVE_BUFFER_SIZE 1500

// define the identifier of trust properties
#define EMAIL 1
#define TELEPHONE 2
#define ADDRESS 3

// defines for the identifier
#define ORG_IDENTIFIER_SIZE 20
#define USER_IDENTIFIER_SIZE 10
#define DEVICE_IDENTIFIER_SIZE 5
#define IDENTIFIER_SIZE ORG_IDENTIFIER_SIZE + USER_IDENTIFIER_SIZE + DEVICE_IDENTIFIER_SIZE + 2

// defines for the enrollment request
#define SERIALIZED_ENR_REQ_OBJ_STRING IDENTIFIER_SIZE + 6

// defines for the response
#define LENGTH_OF_CONTENT_TYPE_HEADER 24
#define CONTENT_TYPE_HEADER "Content-Type: text/plain"
#define LENGTH_OF_CONTENT_LENGTH_HEADER 16
#define CONTENT_LENGTH_HEADER "Content-Length: "

// Safety checks
#define MAX_PROPERTY_VALUE_LENGTH 256
#define MIN_PROPERTY_VALUE_LENGTH 1

// Validation macros
#define IS_VALID_PROPERTY_ID(id) ((id) >= EMAIL && (id) <= ADDRESS)
#define IS_VALID_BUFFER_SIZE(size) ((size) > 0 && (size) <= RECEIVE_BUFFER_SIZE)

#endif
