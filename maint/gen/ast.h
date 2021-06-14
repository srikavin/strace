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

struct ast_type {
	char *name;
	struct ast_type_option_list *options;
};

struct ast_type_option_list {
	struct ast_type_option *option;
	struct ast_type_option_list *next;
};

enum ast_type_option_child {
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

struct ast_type *
create_or_get_type(char *name, struct ast_type_option_list *options);

struct ast_type_option *
create_or_get_type_option_number(struct ast_number number);

struct ast_type_option *
create_or_get_type_option_nested(struct ast_type *child);

void
display_ast_tree(struct ast_node *root);

void
free_ast_tree(struct ast_node *root);

#endif
