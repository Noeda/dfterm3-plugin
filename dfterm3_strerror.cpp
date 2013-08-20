#define _XOPEN_SOURCE 700
#undef _GNU_SOURCE
#include <string>
#include <cstring>

using namespace std;

string errnoToString( int error_number )
{
#ifndef _WIN32
    char buffer[500];
    int succeeded = strerror_r( error_number, buffer, 499 );
    buffer[499] = 0; // not sure if this is necessary

    if ( succeeded != 0 ) {
        if ( errno == EINVAL ) {
            return "<invalid error code passed to strerror_r()>";
        }
        sprintf( buffer, "<strerror_r() failed with errno == %d>", errno );
    }

    return string(buffer);
#else
    char buffer[500];
    strerror_s( buffer, 499, error_number );
    buffer[499] = 0;
    return string(buffer);
#endif
}

