/* xorav_error.h */
#ifndef XORAV_ERROR_H
#define XORAV_ERROR_H

#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

    static int XORAV_OK = 0;
    static int XORAV_ERR_ERROR = 1;
    static int XORAV_ERR_NULL_PTR = 2;
    static int XORAV_ERR_REALLOCATED = 3;
    static int XORAV_ERR_SIZE_ZERO = 4;
    static int XORAV_ERR_OVERFLOW = 5;
    static int XORAV_ERR_BUFF_OVERUN = 6;

#ifdef __cplusplus
}
#endif
#endif