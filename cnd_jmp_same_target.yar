import "elf"
import "pe"

rule conditional_jump_same_target {
    meta:
        description = "detects conditional jumps to same target address"
        author = "kvmc"

    strings:
        $cndJmp = { 0F 8? ?? ?? 00 00 0F 8? ?? ?? 00 00 }


    condition:
    	(elf.type or pe.is_pe) and (@cndJmp[8-11] - @cndJmp[2-5] == 6)

} 
