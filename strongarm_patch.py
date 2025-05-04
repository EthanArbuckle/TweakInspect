import sys
from typing import Dict, List, Tuple

try:
    import strongarm.macho.dyld_info_parser as sa_dyld_parser
    import strongarm.macho.macho_definitions as sa_defs
    from strongarm.macho.arch_independent_structs import MachoDyldChainedPtr64Bind, MachoDyldChainedPtr64Rebase
    from strongarm.macho.dyld_info_parser import DyldBoundSymbol
    from strongarm.macho.macho_binary import MachoBinary
    from strongarm.macho.macho_definitions import MachoDyldChainedPtrFormat, VirtualMemoryPointer
    from strongarm.macho.utils import int24_from_value

except ImportError as exc:
    print(f"Error importing strongarm stuff {exc}")
    sys.exit(1)

try:
    sa_defs.MachoDyldChainedPtrFormat.DYLD_CHAINED_PTR_ARM64E = 1
except Exception as exc:
    print(f"Failed to add a new field to MachoDyldChainedPtrFormat: {exc}")
    sys.exit(1)


@staticmethod
def new_process_fixup_pointer_chain(
    binary: MachoBinary,
    dyld_bound_symbols_table: List[DyldBoundSymbol],
    chain_base: VirtualMemoryPointer,
    pointer_format: MachoDyldChainedPtrFormat,
) -> Tuple[Dict[VirtualMemoryPointer, VirtualMemoryPointer], Dict[VirtualMemoryPointer, DyldBoundSymbol]]:
    rebased_pointers: Dict[VirtualMemoryPointer, VirtualMemoryPointer] = {}
    dyld_bound_addresses_to_symbols: Dict[VirtualMemoryPointer, DyldBoundSymbol] = {}
    virtual_base = binary.get_virtual_base()
    for _ in range(10000):
        chained_rebase_ptr = binary.read_struct(chain_base, MachoDyldChainedPtr64Rebase)
        if chained_rebase_ptr.bind == 1:
            chained_bind_ptr = binary.read_struct(chain_base, MachoDyldChainedPtr64Bind)
            ordinal = int24_from_value(chained_bind_ptr.ordinal)
            bound_symbol = dyld_bound_symbols_table[ordinal]
            dyld_bound_addresses_to_symbols[chain_base + virtual_base] = bound_symbol
            chain_base += chained_bind_ptr.next * 4
        else:
            if pointer_format == MachoDyldChainedPtrFormat.DYLD_CHAINED_PTR_64_OFFSET:
                rebase_target = virtual_base + chained_rebase_ptr.target
            elif pointer_format == MachoDyldChainedPtrFormat.DYLD_CHAINED_PTR_64:
                rebase_target = chained_rebase_ptr.target
            elif pointer_format == MachoDyldChainedPtrFormat.DYLD_CHAINED_PTR_ARM64E:
                rebase_target = virtual_base + chained_rebase_ptr.target
            else:
                raise NotImplementedError(f"Unsupported chained pointer format: {pointer_format}")

            rebased_pointers[VirtualMemoryPointer(chain_base + virtual_base)] = VirtualMemoryPointer(rebase_target)
            chain_base += chained_rebase_ptr.next * 4

        if chained_rebase_ptr.next == 0:
            break
    else:
        raise ValueError("Failed to find end of fixup pointer chain")
    return rebased_pointers, dyld_bound_addresses_to_symbols


sa_dyld_parser.DyldInfoParser._process_fixup_pointer_chain = new_process_fixup_pointer_chain  # ignore
