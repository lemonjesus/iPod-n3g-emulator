#ifndef _DEBUGGER_H_
#define _DEBUGGER_H_

int debugger_init(uc_engine* uc);
void hook_code(uc_engine* uc, uint32_t address, uint32_t size, void* user_data);

#endif