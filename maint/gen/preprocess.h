#ifndef PREPROCESS_H
#define PREPROCESS_H

/*
 * Stores nested #ifdef/#ifndef statements sequentially (as a stack)
 *
 * #ifdef test1
 * #ifdef test2 && test3
 * #endif
 * #endif
 *
 * is stored as count = 2, ["#ifdef test1", "#ifdef test2 && test3"]
 */
struct statement_condition {
	size_t count;
	char *values[];
};

/*
 * Stores define and include statements
 */
struct preprocessor_statement {
	struct ast_loc loc;

	// can be NULL
	struct statement_condition *conditions;

	char *value;
};

struct preprocessor_statement_list {
	struct preprocessor_statement stmt;
	struct preprocessor_statement_list *next;
};

struct struct_def {
	struct ast_loc loc;

	char *name;
	struct statement_condition *conditions;
	// TODO
};

struct syscall_argument {
	char *name;
	struct ast_type *type;
};

struct syscall {
	struct ast_loc loc;

	// can be NULL
	struct statement_condition *conditions;

	// name of the syscall
	char *name;

	// the return value of the syscall
	struct ast_type ret;

	// the defined arguments
	size_t arg_count;
	struct syscall_argument args[];
};

/*
 * A group of syscall variants.
 *
 * The child syscall_groups will be output first, then the base syscall
 * will be generated.
 */
struct syscall_group {
	struct syscall *base;

	size_t child_count;
	struct syscall_group *children;
};

struct processed_ast {
	struct preprocessor_statement_list *preprocessor_stmts;
	struct struct_def *struct_stmts;
	size_t syscall_group_count;
	struct syscall_group *syscall_groups;
};

struct processed_ast *
preprocess(struct ast_node *root);

#endif
