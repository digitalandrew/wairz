import type * as Monaco from 'monaco-editor'

/**
 * Register a "shell" language with Monarch tokenizer for
 * bash / sh script syntax highlighting.
 * Call once via Monaco's beforeMount callback.
 */
export function registerShellLanguage(monaco: typeof Monaco) {
  if (monaco.languages.getLanguages().some((l) => l.id === 'shell')) return

  monaco.languages.register({ id: 'shell' })

  monaco.languages.setMonarchTokensProvider('shell', {
    defaultToken: '',

    keywords: [
      'if', 'then', 'else', 'elif', 'fi',
      'for', 'while', 'until', 'do', 'done',
      'case', 'esac', 'in',
      'function', 'select',
      'return', 'exit',
      'break', 'continue',
      'declare', 'typeset', 'local', 'export', 'readonly',
      'unset', 'shift',
      'source', 'eval', 'exec',
      'trap', 'wait',
    ],

    builtins: [
      'echo', 'printf', 'read', 'cd', 'pwd', 'pushd', 'popd',
      'test', 'true', 'false',
      'set', 'shopt', 'getopts',
      'umask', 'ulimit',
      'alias', 'unalias', 'type', 'hash',
      'enable', 'builtin', 'command',
      'let', 'dirs', 'jobs', 'kill', 'disown', 'bg', 'fg',
      'suspend', 'logout', 'times', 'history', 'fc',
      'bind', 'complete', 'compgen',
    ],

    operators: [
      '=', '==', '!=', '-eq', '-ne', '-lt', '-le', '-gt', '-ge',
      '-z', '-n', '-f', '-d', '-e', '-r', '-w', '-x', '-s',
      '-L', '-h', '-p', '-b', '-c', '-t', '-o', '-a',
      '&&', '||', '!', '|', '&', ';', ';;',
      '>>', '<<', '>', '<', '>&', '<&', '2>&1', '2>', '/dev/null',
    ],

    tokenizer: {
      root: [
        // Shebang
        [/^#!.*$/, 'metatag'],

        // Comments
        [/#.*$/, 'comment'],

        // Here-document start
        [/(<<-?)\s*(['"]?)(\w+)\2/, { token: 'string.heredoc.delimiter', next: '@heredoc.$3' }],

        // Double-quoted strings (allow interpolation)
        [/"/, 'string', '@doubleString'],

        // Single-quoted strings (literal)
        [/'/, 'string', '@singleString'],

        // Backtick command substitution
        [/`/, 'string.backtick', '@backtick'],

        // $(...) command substitution
        [/\$\(/, 'variable', '@commandSub'],

        // Variables
        [/\$\{[^}]*\}/, 'variable'],
        [/\$[A-Za-z_]\w*/, 'variable'],
        [/\$[0-9@#?!\-*$]/, 'variable'],

        // Numbers
        [/0[xX][0-9a-fA-F]+/, 'number.hex'],
        [/0[0-7]+/, 'number.octal'],
        [/\d+/, 'number'],

        // Identifiers / keywords
        [
          /[a-zA-Z_]\w*/,
          {
            cases: {
              '@keywords': 'keyword',
              '@builtins': 'predefined',
              '@default': 'identifier',
            },
          },
        ],

        // Operators and punctuation
        [/[;|&]{1,2}/, 'delimiter'],
        [/[<>]{1,2}/, 'delimiter'],
        [/[()]/, 'delimiter.parenthesis'],
        [/[[\]]/, 'delimiter.bracket'],
        [/[{}]/, 'delimiter.curly'],
        [/[=!]=?/, 'operator'],
        [/-[a-zA-Z]+/, 'operator'],

        // Whitespace
        [/\s+/, 'white'],
      ],

      doubleString: [
        [/\$\{[^}]*\}/, 'variable'],
        [/\$[A-Za-z_]\w*/, 'variable'],
        [/\$[0-9@#?!\-*$]/, 'variable'],
        [/\\[\\$`"nrt]/, 'string.escape'],
        [/"/, 'string', '@pop'],
        [/[^"$\\]+/, 'string'],
        [/./, 'string'],
      ],

      singleString: [
        [/'/, 'string', '@pop'],
        [/[^']+/, 'string'],
      ],

      backtick: [
        [/`/, 'string.backtick', '@pop'],
        [/[^`]+/, 'string.backtick'],
      ],

      commandSub: [
        [/\)/, 'variable', '@pop'],
        { include: 'root' },
      ],

      heredoc: [
        [/^(\s*)(\w+)$/, {
          cases: {
            '$2==$S2': { token: 'string.heredoc.delimiter', next: '@pop' },
            '@default': 'string.heredoc',
          },
        }],
        [/.*$/, 'string.heredoc'],
      ],
    },
  } as Monaco.languages.IMonarchLanguage)
}
