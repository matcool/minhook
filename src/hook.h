#pragma once

#ifdef __cplusplus
extern "C" {
#endif

void EnterSpinLock(void);
void LeaveSpinLock(void);

#ifdef __cplusplus
}
#endif
