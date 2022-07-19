OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(code_64)
SECTIONS
{
 . = 0x8000000000;
 .text : {
 stext = .;
  *(.text.reset)
  *(.text)
  *(.text.*)
 }
 . = ALIGN(4096);
 etext = .;
 .bss : {
 sbss = .;
  *(.bss)
  *(.bss._*)
 }
 . = ALIGN(4096);
 ebss = .;
 .data : {
 sdata = .;
  *(.data)
  *(.data._*)
  *(.data.rel*)
  *(.data.guids)
 }
 edata = .;
 /DISCARD/ : {
  *(.comment)
  *(.discard)
  *(.discard.*)
  *(.dynamic)
  *(.eh_frame)
  *(.note.GNU-stack)
  *(.note.gnu.build-id)
 }
}
