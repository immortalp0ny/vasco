from typing import Any, Dict, Optional
from dataclasses import dataclass

import ida_bytes
import ida_segment
import ida_nalt

from triton import (
    TritonContext, MemoryAccess,
    CALLBACK
)

from ..utils.ida_utils import get_size_of_ptr
from ..utils.tri import tri_get_single_instruction

from .heap import easy_heap_t
from .const import (
    MEMORY_TAG_IMPORT,
    MEMORY_TAG_SEG,
    DEFAULT_ALIGNMENT,
    DEFAULT_HEAP_BASE,
    DEFAULT_HEAP_SIZE,
    DEFAULT_STACK_BOTTOM,
    DEFAULT_STACK_SIZE
)



@dataclass
class ida_func_emulator_memory_chunk_t:
    address:   int
    tag:       str
    alignment: int
    size:      int
    perm:      str
    read_cb:   Any
    write_cb:  Any
    released:  bool
    heap:      bool


@dataclass
class ida_func_emulator_memory_import_t:
    ia:       int
    resolved: int
    fullname: str    


class ida_func_emulator_memory_t:
    def __init__(
            self,
            emu,
            sp_bottom: int = DEFAULT_STACK_BOTTOM,
            sp_size:   int = DEFAULT_STACK_SIZE,
            alignment: int = DEFAULT_ALIGNMENT,
            heap: easy_heap_t = None
        ):
        self._heap = heap
        if not self._heap:
            self._heap = easy_heap_t(
                DEFAULT_HEAP_BASE, DEFAULT_HEAP_SIZE
            )

        self._ptrsz = get_size_of_ptr()

        self._stack_range = (sp_bottom, sp_bottom + sp_size)
        self._heap_range  = (self._heap.base, self._heap.base + self._heap.size)

        self._alignment = alignment

        self._emu = emu

        # @immortalp0ny: index of all allocated memory in emu instance
        self._mapped: Dict[int, ida_func_emulator_memory_chunk_t] = {}

        self._emu.ctx.addCallback(CALLBACK.GET_CONCRETE_MEMORY_VALUE, self._tri_cb_mem_read)
        self._emu.ctx.addCallback(CALLBACK.SET_CONCRETE_MEMORY_VALUE, self._tri_cb_mem_write)

        # @immortalp0ny: setup stack
        sp_back_off = int(
            (self._stack_range[1] - self._stack_range[0]) / 2
        )
        self._emu.ctx.setConcreteRegisterValue(
            self._emu.ctx.registers.rsp,
            self._stack_range[1] - sp_back_off 
        )
        
        # @immortalp0ny: index of all binary imports 
        self._imports: Dict[str, ida_func_emulator_memory_import_t] = {}
        # @immortalp0ny: total number of binary imports 
        self._nimps = 0

        self._init_imports()
        self._init_segments()

    def _init_segments(self):
        for i in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(i)
            
            chunk = ida_func_emulator_memory_chunk_t(
               address   = seg.start_ea,
               tag       = MEMORY_TAG_SEG,
               alignment = self._alignment,
               size      = seg.end_ea - seg.start_ea,
               perm      = 'RWX',
               read_cb   = self._cb_read_mem_from_ida,
               write_cb  = None,
               released  = False,
               heap      = False 
            )

            self._mapped[seg.start_ea] = chunk
            
    def _init_imports(self):
        nimps = ida_nalt.get_import_module_qty()
        
        for i in range(nimps):
            module_name = ida_nalt.get_import_module_name(i)
            if not module_name:
                module_name = "<unnamed>"

            def cb(ea, name, ordinal):
                if not name:
                    fullname = f"{module_name}!{ordinal}"
                else:
                    fullname = f"{module_name}!{name}"
                
                self._imports.setdefault(
                    fullname,
                    ida_func_emulator_memory_import_t(
                        ia=ea,
                        fullname=fullname,
                        resolved=0
                    )
                )
                
                self._nimps += 1

                return True
            
            ida_nalt.enum_import_names(i, cb)
        
        # @immortap0ny: I choose 0xCC (int3) because my idea was that every import should be handled manualy
        #               or analysis should not be able to perform under code with unhandled import.
        #               BTW it easy to change it from int3 to ret or any x86 asm code but why?
        self._imports_code = self.heap_new(
            MEMORY_TAG_IMPORT,
            [0xCC] * (self._nimps * self._ptrsz)
        )

        self._mapped[self._imports_code].heap = False
        
        j = self._imports_code
        for k in self._imports.keys():
            func_import = self._imports[k]
            func_import.resolved = j
            self._emu.ctx.setConcreteMemoryValue(MemoryAccess(func_import.ia, self._ptrsz), j)

            j += self._ptrsz

    def _cb_read_mem_from_ida(self, ctx: TritonContext, memaccess: MemoryAccess):
        if ctx.isConcreteMemoryValueDefined(memaccess):
            return
        
        memaddr = memaccess.getAddress()
        memsize = memaccess.getSize()

        memdata = ida_bytes.get_bytes(memaddr, memsize)
        if not memdata:
            return

        self._emu.ctx.setConcreteMemoryAreaValue(memaddr, memdata)
             
    def _tri_cb_mem_read(self, ctx: TritonContext, memaccess: MemoryAccess):
        memaddr = memaccess.getAddress()
        memsize = memaccess.getSize()
    
        for k, v in self._mapped.items():
            b = memaddr
            e = memaddr + memsize

            if k <= b and e <= (k + v.size):
                if 'R' not in v.perm:
                    raise RuntimeError(
                        f"read access is restricted to chunk (base={k}, size={v.size}, tag={v.tag})"
                    )
                
                chunk_read_cb = v.read_cb
                if chunk_read_cb:
                    chunk_read_cb(ctx, memaccess)
                
                break

    def _tri_cb_mem_write(self, ctx: TritonContext, memaccess: MemoryAccess, value):
        memaddr = memaccess.getAddress()
        memsize = memaccess.getSize()

        for k, v in self._mapped.items():
            b = memaddr
            e = memaddr + memsize
            if k <= b and e <= (k + v.size):
                if 'W' not in v.perm:
                    raise RuntimeError(
                        f"write access is restricted to chunk (base={k}, size={v.size}, tag={v.tag})"
                    )
                
                chunk_write_cb = v.write_cb
                if chunk_write_cb:
                    chunk_write_cb(ctx, memaccess)
                
                break

    @property
    def memmap(self):
        return self._mapped
    
    @property
    def heap_range(self):
        return self._heap_range
    
    @property
    def stack_range(self):
        return self._stack_range
    
    def is_import(self, ea: int) -> bool:
        imports_chunk = self._mapped[self._imports_code]
        
        begin = imports_chunk.address
        end = imports_chunk.address + imports_chunk.size
        
        if begin <= ea < end:
            return True
        
        return False
    
    def is_heap(self, ea: int) -> bool:
        chunk = self._mapped[ea]
        if not chunk:
            return False
        
        return chunk.heap

    def is_stack(self, ea: int) -> bool:
        return self._stack_range[0] <= ea < self._stack_range[1]

    def map_memory(self, address: int, data: bytes, tag: str, is_heap: bool = False, perm: str = "RWX", read_cb = None, write_cb = None, redefinition: bool = False):
        mapped_chunk_info = self._mapped.get(address, {})
        if mapped_chunk_info and not redefinition:
            raise KeyError(
                f"chunk redefintion addr={address} new_size={len(data)} old_size={mapped_chunk_info.size} tag={tag}"
            )
        
        aligned = int((address + (self._alignment - 1)) / self._alignment) * self._alignment
        if aligned != address:
            raise ValueError(f'address is not aligned properly addr={address}')
        
        chunk = ida_func_emulator_memory_chunk_t(
            address   = aligned,
            tag       = tag,
            alignment = self._alignment,
            size      = len(data),
            perm      = perm,
            read_cb   = read_cb,
            write_cb  = write_cb,
            released  = False,
            heap      = is_heap
        )
        self._mapped[address] = chunk

        self._emu.ctx.setConcreteMemoryAreaValue(
            aligned, data, callbacks=False 
        )

        return self._mapped[address]

    def heap_new(self, tag: str, data: bytes, perm: str = "RWX", read_cb = None, write_cb = None, fixed_address: int = None):
        aligned = int((len(data) + (self._alignment - 1)) / self._alignment) * self._alignment

        if aligned != len(data):
            data += bytes([0x00] * (aligned - len(data)))

        heap_address = self._heap.acquire(aligned, fixed_address)
        if heap_address is None:
            raise RuntimeError('failed to acquire heap address')

        chunk = self.map_memory(
            heap_address,
            data,
            tag,
            is_heap=True,
            perm=perm,
            read_cb=read_cb,
            write_cb=write_cb,
            redefinition=False
        )
        
        return chunk.address

    def heap_free(self, address: int):
        chunk = self._mapped.get(address)
        if not chunk:
            raise KeyError(f"attempt to free heap chunk that is not allocated previously")
        
        if chunk.released:
            raise RuntimeError(f"attempt to release already released chunk")

        chunk.released = True

    def get_content(self, address: int) -> bytes:
        chunk = self._mapped.get(address)
        if not chunk:
            return bytes()
        
        size = chunk.size

        return self._emu.ctx.getConcreteMemoryAreaValue(
            address, size, callbacks=False
        )

    def get_chunk(self, address: int) -> Optional[ida_func_emulator_memory_chunk_t]:
        return self._mapped.get(address)
    
    def set_chunk_read_cb(self, address: int, fn):
        if address not in self._mapped:
            raise KeyError(f"address={address:08X} is not found")
        
        self._mapped[address].read_cb = fn

    def set_chunk_write_cb(self, address: int, fn):
        if address not in self._mapped:
            raise KeyError(f"address={address:08X} is not found")
        
        self._mapped[address].write_cb = fn

    def find_chunk(self, address: int) -> Optional[ida_func_emulator_memory_chunk_t]:
        for k, v in self._mapped.items():
            if k <= address < (k + v.size):
                return v

    def get_import(self, fullname: str) -> Optional[ida_func_emulator_memory_import_t]:
        return self._imports.get(fullname)
    