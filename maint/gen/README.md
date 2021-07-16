Syscall Definitions
====

This syscall definition language is based on the [syzkaller description language](https://github.com/google/syzkaller/blob/master/docs/syscall_descriptions.md).

All non-syscall statements maintain their relative ordering and are placed
before syscall statements in the generated C code.

## Syntax

### Types

Types have the following format `type_name[type_option]`. The `type_name` can include alphanumeric characters and `$_`. The `type_option` can be another type or a number.

Numbers can be specified as a decimal number (`1234`) or as a hex number (`0x4D2`).

The default types are the following:
 * standard C types: `void`, `int`, `char`, `long`, `uint`, `ulong`, `longlong`, `ulonglong`, `double`, `float`
 * `stddef.h` types: `size_t`, `ssize_t`, ...
 * `stdint.h` types: `uint8_t`, `int8_t`, `uint64_t`, `int64_t`, ...
 * kernel types: `kernel_long_t`, `kernel_ulong_t`, ...
 * `fd`: A file descriptor
 * `tid`: A thread id
 * `string`: A null terminated char buffer
 * `path` A null terminated path string
 * `stringnoz[n]`: A non-null terminated char buffer of length `n`
 * `const[x]`: A constant of value `x` that inherits its parent type
 * `const[x:y]`: A constant with a value between `x` and `y` (inclusive) that inherits its parent type
 * `ptr[dir, typ]`: A pointer to object of type `typ`; direction can be `in`, `out`, `inout`
 * `array[typ, n]`: An buffer of `n` objects with type `typ`
 * `ref[argname]`: A reference to the value of another parameter with name `argname` or `@ret`
 * `xor_flags[flag_typ, ???]`: A integer type containing mutually exclusive flags of type `flag_typ`
 * `or_flags[flag_typ, ???]`: A integer type containing flags that are ORed together of type `flag_typ`

 User defined types include structs, unions, and other types from included header files.

Constants (`const`) can only be used within variant syscalls.

### Syscalls
Syscall definitions have the format
```
syscall_name (arg_type1 arg_name1, arg_type2 arg_name2, ...) return_type
```

The `return_type` is optional if no special printing mode is needed.

Some system calls have various modes of operations. Consider the `fcntl` syscall.
Its second parameter determines the types of the remaining arguments. To
handle this, a variant syscall definition can be used:
```
fcntl(filedes fd, cmd xor_flags[fcntl_cmds, F_???], arg kernel_ulong_t) kernel_ulong_t
fcntl$F_DUPFD(filedes fd, cmd const[F_DUPFD], arg kernel_ulong_t) fd
fcntl$F_DUPFD_CLOEXEC(filedes fd, cmd const[F_DUPFD_CLOEXEC], arg kernel_ulong_t) fd
...
```

The `$` character is used to indicate that a syscall is a variant of another one.
The `const` parameters of a variant syscall will be used to determine which
variant to use. If no variant syscalls match, the base syscall will be used.

### Structs

Struct definitions have the format
```
struct_name {
    element_name element_type
    element_name2 element_type2
    ...
} [attribute]
```

The attribute field is optional. A struct must contain at least one element.

### Flags

Flags have the format
```
flagname = FLAG_VALUE1, FLAG_VALUE2, FLAG_VALUE3, ...
```
Each FLAG_VALUE is assumed to have been defined in a header file or by a define statement.

TODO: Consider how to specify mappings to existing xlat definitions.

### #import

Import statements have the format
```
#import "filename.def"
```

The contents of the `filename.def` will be treated as if they were placed in the current file.

### #ifdef/#ifndef

Ifdef, ifndef statements have the format
```
#ifdef condition
#ifndef condition
#endif
#endif
```

Ifdef, ifndef, and define statements will be included as-is in the generated output.
Unlike C, these cannot be placed in the middle of another statement.

### define/include

Include and define statements have the format
```
define DEBUG 1
include "filename"
include <filename>
```

Include and define statements will be included as-is in the generated output.
