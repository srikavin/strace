#ifndef AST_H
#define AST_H

#include <stdbool.h>
#include <stdint.h>

struct ast_number {
	char *raw;
	intmax_t val;
};

enum ast_node_type {
	AST_IFDEF,
	AST_SYSCALL,
	AST_DEFINE,
	AST_INCLUDE,
	AST_COMPOUND,
	AST_STRUCT,
	AST_FLAGS
};

struct ast_struct {
	char *name;
	struct ast_struct_element *elements;
};

struct ast_struct_element {
	char *name;
	struct ast_type *type;
	struct ast_struct_element *next;
};

struct ast_syscall {
	char *name;
	struct ast_syscall_arg *args;
	struct ast_type *return_type;
};

struct ast_syscall_arg {
	char *name;
	struct ast_type *type;
	struct ast_syscall_arg *next;
};

enum standard_types {
	// non-special type
	TYPE_BASIC,
	// stringnoz[len]
	TYPE_STRINGNOZ,
	// const[typ, val]
	TYPE_CONST,
	// ptr[dir, typ]
	TYPE_PTR,
	// array[typ, len]
	TYPE_ARRAY,
	// ref[argname]
	TYPE_REF,
	// xorflags[flag_typ]
	TYPE_XORFLAGS,
	// orflags[flag_typ]
	TYPE_ORFLAGS
};

#define IS_IN_PTR(x) ((x)->type == TYPE_PTR && \
((x)->ptr.dir == PTR_DIR_INOUT || (x)->ptr.dir == PTR_DIR_IN))

#define IS_OUT_PTR(x) ((x)->type == TYPE_PTR && \
((x)->ptr.dir == PTR_DIR_INOUT || (x)->ptr.dir == PTR_DIR_OUT))

#define IS_INOUT_PTR(x) ((x)->type == TYPE_PTR && (x)->ptr.dir == PTR_DIR_INOUT)

enum ptr_dir {
	PTR_DIR_IN,
	PTR_DIR_OUT,
	PTR_DIR_INOUT,
};

struct ast_type {
	enum standard_types type;
	char *name;
	struct ast_type_option_list *options;
	union {
		struct {
			struct ast_type_option *len;
		} stringnoz;
		struct {
			struct ast_type_option *value;
		} constt;
		struct {
			enum ptr_dir dir;
			struct ast_type *type;
		} ptr;
		struct {
			struct ast_type_option *type;
			struct ast_type_option *len;
		} array;
		struct {
			char *argname;
		} ref;
		struct {
			struct ast_type_option *flag_type;
		} xorflags;
		struct {
			struct ast_type_option *flag_type;
		} orflags;
	};
};

struct ast_type_option_list {
	struct ast_type_option *option;
	struct ast_type_option_list *next;
};

enum ast_type_option_child {
	AST_TYPE_CHILD_RANGE,
	AST_TYPE_CHILD_NUMBER,
	AST_TYPE_CHILD_TYPE
};

struct ast_type_option {
	enum ast_type_option_child child_type;
	union {
		struct ast_type *type;
		struct ast_number number;
	};
};

struct ast_flag_values {
	char *name;
	struct ast_flag_values *next;
};

struct ast_node {
	enum ast_node_type type;
	struct {
		int lineno;
		int colno;
	} loc;

	// used when this node's parent is AST_COMPOUND
	struct ast_node *next;

	union {
		struct ast_syscall syscall;
		struct ast_struct ast_struct;
		struct {
			char *value;
			bool invert;
			struct ast_node *child;
		} ifdef;
		struct {
			char *value;
		} include;
		struct {
			char *value;
		} define;
		struct {
			struct ast_node *children;
		} compound;
		struct {
			char *name;
			struct ast_flag_values *values;
		} flags;
	};
};

struct ast_node *
create_ast_node(enum ast_node_type type, void *location);

struct ast_type_option_list *
create_ast_type_option_list(struct ast_type_option *cur, struct ast_type_option_list *next);

struct ast_struct_element *
create_ast_struct_element(char *name, struct ast_type *type, struct ast_struct_element *next);

struct ast_syscall_arg *
create_ast_syscall_arg(char *name, struct ast_type *type, struct ast_syscall_arg *next);

struct ast_flag_values *
create_ast_flag_values(char *name, struct ast_flag_values *next);

/*
 * On error, returns NULL and sets an error string to error.
 */
struct ast_type *
create_or_get_type(char **error, char *name, struct ast_type_option_list *options);

struct ast_type_option *
create_or_get_type_option_number(struct ast_number number);

struct ast_type_option *
create_or_get_type_option_nested(struct ast_type *child);

void
display_ast_tree(struct ast_node *root);

void
free_ast_tree(struct ast_node *root);

#endif
