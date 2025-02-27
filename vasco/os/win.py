from functools import partial

from ..emu.cc import (
    ida_func_cc_win_stdcall_x86_t,
    ida_func_cc_win_fastcall_amd64_t
)
from ..utils.ida_utils import get_size_of_ptr, find_ea_by_name
from ..utils.log import vasco_log

import ida_funcs
import ida_ida


class windows_hooks_t:
    def __init__(self, emu, max_dyn_size: int = 65536):
        self._emu = emu
        self._kernel_mode = ida_ida.idainfo_is_kernel_mode()
        self._ctr = 0
        self._max_dyn_size = max_dyn_size
        
        if ida_ida.idainfo_is_64bit():
            self._api_cc = ida_func_cc_win_fastcall_amd64_t()
        else:
            self._api_cc = ida_func_cc_win_stdcall_x86_t()

        self._hooked_imported_api = set(
            ["kernel32!HeapAlloc"]
        )

        emu.set_import_hook("kernel32!HeapAlloc", self.Hook_HeapAlloc)
        emu.set_import_hook("kernel32!HeapFree",  self.Hook_HeapFree)

        self._hooked_function_names = set([
            "Win32AllocPoolWithQuotaZInit",
            "Win32AllocPoolWithQuota",
            "Win32AllocPool",
            "Win32FreePool"
        ])

        self._set_hook_by_name_if_exists("Win32AllocPoolWithQuotaZInit", partial(self.Hook_Win32AllocPool, True))
        self._set_hook_by_name_if_exists("Win32AllocPoolWithQuota",      partial(self.Hook_Win32AllocPool, False))
        self._set_hook_by_name_if_exists("Win32AllocPool",               partial(self.Hook_Win32AllocPool, False))
        self._set_hook_by_name_if_exists("Win32FreePool",                self.Hook_Win32FreePool)


    @property
    def hooked_imported_api(self):
        return self._hooked_imported_api
    
    @property
    def hooked_function_names(self):
        return self._hooked_function_names

    def _set_hook_by_name_if_exists(self, name: str, fn):
        ea = find_ea_by_name(name)
        if not ea:
            return
        
        self._emu.set_hook(ea, fn)

    def _dyn_new(self, emu, size: int, tag: str, perm: str, cb_read, cb_write, fill_byte = 0):
        addr = emu.mem.heap_new(
            tag,
            [fill_byte] * size,
            perm=perm,
            read_cb=cb_read,
            write_cb=cb_write
        )

        vasco_log(
            '?',
            f"windows_hooks_t(): dynamic memory assigned addr={addr:08X} tag={tag} size={size:08X} perm={perm}"
        )

        return addr
    
    def _dyn_release(self, emu, address: int):
        chunk = emu.mem.get_chunk(address)
        if not chunk:
            vasco_log(
                '!',
                f"windows_hooks_t(): dynamic memory released but it previously was not allocated addr={address:08X}"
            )
            return
        
        chunk.released = True

        vasco_log(
            '?',
            f"windows_hooks_t(): dynamic memory released addr={address:08X} tag={chunk.tag} size={chunk.size:08X} perm={chunk.perm}"
        )

    def Hook_HeapAlloc(self, emu):
        size = self._api_cc.get_arg(emu.ctx, 2)

        if size == 0:
            size = 4096

        if size > self._max_dyn_size:
            size = self._max_dyn_size

        dynmem = self._dyn_new(
            emu,
            size,
            f"mem.dyn.heap.{self._ctr}",
            'RW',
            None,
            None
        )

        self._api_cc.simulate_return(emu.ctx, dynmem)

        self._ctr += 1

    def Hook_HeapFree(self, emu):
        dynmem = self._api_cc.get_arg(emu.ctx, 2)

        self._dyn_release(
            emu,
            dynmem
        )

        self._api_cc.simulate_return(emu.ctx, 1)
        
    def Hook_GetProcessHeap(self, emu):
        self._api_cc.simulate_return(emu.ctx, 0xAAAAAAAA)

    def Hook_Win32AllocPool(self, should_zinit: bool, emu):
        size = emu.cc.get_arg(emu.ctx, 0)
        if size == 0:
            size = 4096

        if size > self._max_dyn_size:
            size = self._max_dyn_size

        dynmem = self._dyn_new(
            emu, size, f"mem.dyn.win32pool.{self._ctr}", 'RW', None, None, fill_byte = 0 if should_zinit else 0xCA
        )

        self._ctr += 1

        emu.cc.simulate_return(emu.ctx, dynmem)

    def Hook_Win32FreePool(self, emu):
        emu.cc.simulate_return(emu.ctx, 0)