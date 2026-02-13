import type * as Monaco from 'monaco-editor'

/**
 * Register a custom "assembly" language with Monarch tokenizer for
 * disassembly output (MIPS, ARM, x86).
 * Call once via Monaco's beforeMount callback.
 */
export function registerAssemblyLanguage(monaco: typeof Monaco) {
  // Don't re-register if already present
  if (monaco.languages.getLanguages().some((l) => l.id === 'assembly')) return

  monaco.languages.register({ id: 'assembly' })

  monaco.languages.setMonarchTokensProvider('assembly', {
    defaultToken: '',
    ignoreCase: true,

    // x86 registers
    x86Regs: [
      'eax','ebx','ecx','edx','esi','edi','esp','ebp','eip',
      'rax','rbx','rcx','rdx','rsi','rdi','rsp','rbp','rip',
      'r8','r9','r10','r11','r12','r13','r14','r15',
      'al','ah','bl','bh','cl','ch','dl','dh',
      'ax','bx','cx','dx','si','di','sp','bp',
      'cs','ds','es','fs','gs','ss',
      'xmm0','xmm1','xmm2','xmm3','xmm4','xmm5','xmm6','xmm7',
    ],

    // ARM registers
    armRegs: [
      'x0','x1','x2','x3','x4','x5','x6','x7','x8','x9',
      'x10','x11','x12','x13','x14','x15','x16','x17','x18','x19',
      'x20','x21','x22','x23','x24','x25','x26','x27','x28','x29','x30','x31',
      'w0','w1','w2','w3','w4','w5','w6','w7','w8','w9',
      'w10','w11','w12','w13','w14','w15',
      'sp','lr','pc','cpsr','spsr',
      'r0','r1','r2','r3','r4','r5','r6','r7','r8','r9',
      'r10','r11','r12','r13','r14','r15',
      'fp','ip','sl',
    ],

    // Common mnemonics across architectures
    mnemonics: [
      // x86
      'mov','movzx','movsx','lea','push','pop','call','ret','jmp',
      'je','jne','jz','jnz','jg','jge','jl','jle','ja','jae','jb','jbe',
      'add','sub','mul','imul','div','idiv','inc','dec','neg','not',
      'and','or','xor','shl','shr','sar','rol','ror',
      'cmp','test','nop','int','syscall','leave','enter',
      'cmove','cmovne','cmovz','cmovnz',
      // ARM
      'ldr','str','ldp','stp','adr','adrp','bl','blr','br','b',
      'cbz','cbnz','tbz','tbnz',
      'adds','subs','ands','orr','eor','lsl','lsr','asr',
      'cset','csel','madd','msub','sdiv','udiv',
      'svc','mrs','msr',
      'beq','bne','blt','bge','bgt','ble','bhi','bls',
      // MIPS
      'lw','sw','lb','sb','lh','sh','lbu','lhu',
      'lui','li','la','addiu','addu','subu',
      'andi','ori','xori','slti','sltiu',
      'sll','srl','sra','sllv','srlv','srav',
      'beq','bne','bgtz','blez','bgez','bltz',
      'j','jal','jr','jalr',
      'mfhi','mflo','mthi','mtlo',
      'mult','multu','divu',
    ],

    tokenizer: {
      root: [
        // Comments
        [/;.*$/, 'comment'],
        [/\/\/.*$/, 'comment'],
        [/#.*$/, 'comment'],

        // Hex addresses / numbers
        [/0x[0-9a-fA-F]+/, 'number.hex'],
        [/\$[0-9a-fA-F]+/, 'number.hex'],

        // Strings
        [/"[^"]*"/, 'string'],
        [/'[^']*'/, 'string'],

        // Labels (word followed by colon at start or after whitespace)
        [/^[a-zA-Z_.][\w.]*:/, 'type.identifier'],
        [/\s[a-zA-Z_.][\w.]*:/, 'type.identifier'],

        // MIPS registers ($a0-$a3, $t0-$t9, $s0-$s7, $v0-$v1, etc.)
        [/\$[a-z][a-z0-9]*/, 'variable.predefined'],
        [/\$\d+/, 'variable.predefined'],

        // Registers and mnemonics — handled via identifier matching
        [
          /[a-zA-Z_][\w]*/,
          {
            cases: {
              '@mnemonics': 'keyword',
              '@x86Regs': 'variable.predefined',
              '@armRegs': 'variable.predefined',
              '@default': 'identifier',
            },
          },
        ],

        // Decimal numbers
        [/-?\d+/, 'number'],

        // Brackets and operators
        [/[[\](){}]/, 'delimiter.bracket'],
        [/[,+\-*]/, 'delimiter'],

        // Whitespace
        [/\s+/, 'white'],
      ],
    },
  } as Monaco.languages.IMonarchLanguage)
}
