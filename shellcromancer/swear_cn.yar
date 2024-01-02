rule Methodology_SwearEngine_Fuck_CN {
  meta:
    author = "@shellcromancer"
    date = "2024-01-01"

    description = "Finds 他妈的 (Tā mā de) in UTF-8"

  strings:
    $f = "\xe4\xbb\x96\xe5\xa6\x88\xe7\x9a\x84"  // 他妈的 in UTF-8

  condition:
    (
      int16(0) == 0x5a4d or  // PE
      uint32(0) == 0x464c457f or  // ELF
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and
    any of them
}
