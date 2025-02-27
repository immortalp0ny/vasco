from typing import List, Optional, Tuple


class easy_heap_t:
    def __init__(self, base: int, size: int):
        self._base = base
        self._size = size
        
        self.reset()

    @property
    def base(self):
        return self._base
    
    @property
    def size(self):
        return self._size
    
    @property
    def free_list(self):
        return list(self._free_list)

    def _fixed_allocate(self, address: int, size: int) -> Optional[int]:
        for i, (block_start, block_size) in enumerate(self.free_list):
            block_end = block_start + block_size

            if block_start > address or address > block_end or (address + size) > block_end:
                continue
            
            self._free_list.pop(i)

            before_size = address - block_start
            after_size = (block_start + block_size) - (address + size)

            if before_size > 0:
                self._free_list.append((block_start, before_size))
            if after_size > 0:
                self._free_list.append((address + size, after_size))

            self._free_list.sort()
            
            return address

    def _free_allocate(self, size: int) -> Optional[int]:
        for i, (block_start, block_size) in enumerate(self._free_list):
            if block_size < size:
                continue
                     
            if block_size == size:
                self._free_list.pop(i) 
            else:
                self._free_list[i] = (
                    block_start + size, block_size - size)
                    
            return block_start

    def reset(self, free_list: List[Tuple[int, int]] = []):
        if free_list:
            self._free_list = free_list
        else:
            self._free_list: List[Tuple[int, int]] = [
                (self._base, self._size)
            ]

    def acquire(self, size: int, address: Optional[int] = None) -> Optional[int]:
        if address is None:
            return self._free_allocate(size)    
        else:
            return self._fixed_allocate(address, size)
        
    def relase(self, address: int):
        pass
        # @immortalp0ny: TODO I should implement this later 

            
