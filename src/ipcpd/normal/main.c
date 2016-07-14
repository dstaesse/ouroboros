#define OUROBOROS_PREFIX "normal-ipcp"

#include <ouroboros/logs.h>
#include <stdbool.h>

#include "fmgr.h"
#include "ribmgr.h"

int main()
{
        if (fmgr_init()) {
                return -1;
        }

        if (ribmgr_init()) {
                fmgr_fini();
                return -1;
        }

        while (true) {

        }

        return 0;
}
