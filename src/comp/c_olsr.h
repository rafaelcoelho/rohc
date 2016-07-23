/*
 * c_olsr.h
 *
 *  Created on: Jul 22, 2016
 *      Author: rscoelho
 */

#ifndef SRC_COMP_C_OLSR_H_
#define SRC_COMP_C_OLSR_H_

#include "rohc_comp_internals.h"

#include <stdint.h>
#include <stdbool.h>
#include "protocols/udp.h"
#include "protocols/olsr.h"

struct sc_olsr_context
{
    /// The previous UDP header
    struct udphdr old_udp;
};
/*No public function*/

#endif /* SRC_COMP_C_OLSR_H_ */
