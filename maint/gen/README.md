Syscall Definitions
====

This syscall definition language is based on the [syzkaller description language](https://github.com/google/syzkaller/blob/master/docs/syscall_descriptions.md).

The ordering of non-syscall statements will be directly reflected in the generated C code. All syscall and ifdef/ifndef statements will be placed at the end of the generated C code with their relative ordering preserved.

## Syntax

### Types

Types have the following format `type_name[type_option]`. The `type_name` can include alphanumeric characters and `$_`. The `type_option` can be another type or a number.

Numbers can be specified as a decimal number (`1234`) or as a hex number (`0x4D2`).

The default types are the following:
 * standard C types: `void`, `int`, `char`, `long`, `uint`, `ulong`, `longlong`, `ulonglong`, `double`, `float`
 * `stddef.h` types: `size_t`, `ssize_t`, ...
 * `stdint.h` types: `uint8_t`, `int8_t`, `uint64_t`, `int64_t`, ...
 * kernel types: `kernel_long_t`, `kernel_ulong_t`, ...
 * `string`: A zero terminated char buffer
 * `stringnoz[n]`: A char buffer of length `n`
 * `const[typ, x]`: A constant of value `x` and type `typ`
 * `ptr[dir, typ]`: A pointer to object of type `typ`; direction can be `in`, `out`, `inout`
 * `array[typ, n]`: An buffer of `n` objects with type `typ`
 * `len[argname]`: A reference to the length of another parameter with name `argname`
 * `xorflags[flag_typ]`: A integer type containing mutually exclusive flags of type `flag_typ`
 * `orflags[flag_typ]`: A integer type containing flags that are ORed together of type `flag_typ`

 User defined types include structs, unions, and other types from included header files.

### Syscalls
Syscall definitions have the format
```
syscall_name (arg_type1 arg_name1, arg_type2, arg_name2) return_type
```

The `return_type` is optional and will default to `void` if left unspecified.

### Structs

Struct definitions have the format
```
struct_name {
    element_name elemeet_type
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

### #ifdef/#ifndef/#define

Ifdef, ifndef, and define statements have the format
```
#ifdef condition
#ifndef condition
#define "definition"
#endif
#endif
```

Ifdef, ifndef, and define statements will be included as-is in the generated output.

### include

Include statements have the format
```
include "filename"
include <filename>
```

Include statements will be included as-is in the generated output.
