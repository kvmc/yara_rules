import "elf"
import "pe"

rule conditional_jump_same_target {
    meta:
        description = "detects conditional jumps to same target address"
        author = "kvmc"

    strings:
        $jojno   = { 0F 80 ?? ?? 00 00  0F 81 ?? ?? 00 00 } 
	$jbjnb   = { 0F 82 ?? ?? 00 00  0F 83 ?? ?? 00 00 }
	$jzjnz   = { 0F 84 ?? ?? 00 00  0F 85 ?? ?? 00 00 }
	$jbejnbe = { 0F 86 ?? ?? 00 00  0F 87 ?? ?? 00 00 }
	$jsjns 	 = { 0F 88 ?? ?? 00 00  0F 89 ?? ?? 00 00 }
	

    condition:
    	(elf.type or pe.is_pe) and 
	( 10 of $jojno and
	  10 of $jbjnb and
	  10 of $jzjnz and
	  10 of $jbejnbe and
	  10 of $jsjns )

} 
