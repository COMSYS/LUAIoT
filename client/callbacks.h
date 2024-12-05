/**
 * @file callbacks.h
 * @author COMSYS, RWTH Aachen University
 * @brief Header file for callback function type definitions.
 * @version 0.1
 * @date 2024-11-01
 */

#ifndef _CALLBACKS_H
#define _CALLBACKS_H
#include <stdint.h>

/**
 * @brief Type definition of the function callback used to send data to the CA.
 * 
 * @param buffer The data buffer to be sent.
 * @param length The length of the data buffer.
 * @param written Pointer to store the number of bytes written.
 */
typedef enum CallbackStatus {
    CALLBACK_SUCCESS = 0,
    CALLBACK_ERROR = -1,
    CALLBACK_TIMEOUT = -2
} CallbackStatus;

typedef CallbackStatus (*sendDataCA)(const char *buffer, int length, int *written);

/**
 * @brief Type definition of the function callback used to receive data from the CA.
 * 
 * @param buffer Pointer to the buffer where the received data will be stored.
 * @param length The length of the data buffer.
 * @param received Pointer to store the number of bytes received.
 */
typedef CallbackStatus (*receiveDataCA)(char **buffer, int length, int *received);

/**
 * @brief Type definition of the function callback used to send evaluation data to an evaluation server.
 * 
 * @param buffer The data buffer to be sent.
 * @param length The length of the data buffer.
 */
typedef CallbackStatus (*sendMeasuredData)(const char *buffer, int length);

#endif
