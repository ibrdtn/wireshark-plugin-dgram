/*
 * packet-dgram-beacon.c
 *
 *  Created on: 10.12.2013
 *      Author: Johannes Morgenroth <morgenroth@ibr.cs.tu-bs.de>
 */

#include "packet-dgram-beacon.h"

/*3rd arg is number of bytes in field (returned)*/
int
evaluate_sdnv(tvbuff_t *tvb, int offset, int *bytecount)
{
    int    value = 0;
    guint8 curbyte;

    *bytecount = 0;

    /*
     * Get 1st byte and continue to get them while high-order bit is 1
     */

    while ((curbyte = tvb_get_guint8(tvb, offset)) & ~SDNV_MASK) {
        if (*bytecount >= (int) sizeof(int)) {
            *bytecount = 0;
            return -1;
        }
        value = value << 7;
        value |= (curbyte & SDNV_MASK);
        ++offset;
        ++*bytecount;
    }

    /*
     * Add in the byte whose high-order bit is 0 (last one)
     */

    value = value << 7;
    value |= (curbyte & SDNV_MASK);
    ++*bytecount;
    return value;
}
