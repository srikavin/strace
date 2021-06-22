#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "ast.h"
#include "deflang.h"
#include "symbols.h"

struct {
	char *type;
	char *standard;
	char *generic;
} basic_printers[] = {
	// %1$s is tcp, %2$s is the arg
	{"fd", "printfd(%1$s, %2$s);", NULL},
	{"string", "printstr(%1$s, %2$s);", "printaddr(%2$s);"},
	{"uid", "printuid(%2$s);", NULL},
	{"gid", "printuid(%2$s);", NULL},
};

struct {
	char *name;
	char *ctype;
} basic_types[] = {
	{"uchar", "unsigned char"},
	{"ushort", "unsigned short"},
	{"uint", "unsigned int"},
	{"ulong", "unsigned long"},
	{"longlong", "long long"},
	{"ulonglong", "unsigned long long"},
	{"longdouble", "long double"},
	{"string", "char"},
	{"size", "size_t"},
	{"gid", "gid_t"}
};

#define ARRAY_LEN(x) (sizeof(x) / sizeof((x)[0]))

/* convenience macros */

#define OUTFI(...) outf_indent(indent_level, out, __VA_ARGS__)

#define OUTF(...) outf(out, __VA_ARGS__)

#define OUTC(c) outc(out, c)

#define OUTSI(s) outs_indent(indent_level, out, s)

#define OUTS(s) outs(out, s)

static void
outf_indent(int indent_level, FILE *out, char *fmt, ...) __attribute__((format(printf, 3, 4)));

static void
outf(FILE *out, char *fmt, ...) __attribute__((format(printf, 2, 3)));

static void
outc(FILE *out, int c)
{
	fputc(c, out);
}

static void
outs(FILE *out, char *s)
{
	fputs(s, out);
}

static void
indent(FILE *out, int indent)
{
	for (int i = 0; i < indent; ++i) {
		outc(out, '\t');
	}
}

static void
outs_indent(int indent_level, FILE *out, char *s)
{
	indent(out, indent_level);
	fprintf(out, "%s", s);
}

static void
outf(FILE *out, char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);

	vfprintf(out, fmt, args);

	va_end(args);
}

static void
outf_indent(int indent_level, FILE *out, char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);

	indent(out, indent_level);
	vfprintf(out, fmt, args);

	va_end(args);
}

struct codegen_ctx {
	char *in_filename;
};

static bool
is_signed_integer_typename(char *name)
{
	char *types[] = {
		"char",
		"short",
		"int",
		"long",
		"longlong",
		"kernel_long_t",
		"ssize_t"
	};

	for (size_t i = 0; i < ARRAY_LEN(types); ++i) {
		if (strcmp(types[i], name) == 0) {
			return true;
		}
	}

	return false;
}

static bool
is_unsigned_integer_typename(char *name)
{
	char *types[] = {
		"uchar",
		"ushort",
		"uint",
		"ulong",
		"ulonglong",
		"kernel_ulong_t",
		"size_t",
		"size"
	};

	for (size_t i = 0; i < ARRAY_LEN(types); ++i) {
		if (strcmp(types[i], name) == 0) {
			return true;
		}
	}

	return false;
}

static char *
type_to_ctype(struct ast_type *type)
{
	if (type->type == TYPE_BASIC) {
		for (size_t i = 0; i < ARRAY_LEN(basic_types); ++i) {
			if (strcmp(type->name, basic_types[i].name) == 0) {
				return basic_types[i].ctype;
			}
		}

		struct ast_node *def = symbol_get(type->name);
		if (def != NULL && def->type == AST_STRUCT) {
			size_t len = sizeof("struct ") + strlen(type->name);
			char *ret = xmalloc(len);
			snprintf(ret, len, "struct %s", type->name);
			return ret;
		}

		return type->name;
	}

	if (type->type == TYPE_PTR) {
		char *underlying = type_to_ctype(type->ptr.type);

		size_t len = strlen(underlying) + sizeof("  /* inout */ *");
		char *ret = xmalloc(len);
		snprintf(ret, len, "%s /* %s */ *", underlying,
				 type->ptr.dir == PTR_DIR_IN ? "in" :
				 (type->ptr.dir == PTR_DIR_OUT ? "out" : "inout"));
		return ret;
	}

	return "#error unknown";
}

/*
 * Outputs a call to a function/macro to print out arg with the given type.
 */
static void
generate_printer(struct codegen_ctx *ctx, FILE *out, char *tcp, char *arg,
				 bool entering, struct ast_type *type, int indent_level)
{
	if (type->type == TYPE_BASIC) {
		if (is_signed_integer_typename(type->name)) {
			outf_indent(indent_level, out, "PRINT_VAL_D(%s);\n", arg);
			return;
		} else if (is_unsigned_integer_typename(type->name)) {
			outf_indent(indent_level, out, "PRINT_VAL_U(%s);\n", arg);
			return;
		}

		for (size_t i = 0; i < ARRAY_LEN(basic_printers); ++i) {
			if (strcmp(type->name, basic_printers[i].type) == 0) {
				if (basic_printers[i].generic) {
					OUTFI("if (syserror(tcp)) {\n");
					indent_level++;
					OUTFI(basic_printers[i].generic, tcp, arg);
					OUTC('\n');
					indent_level--;
					OUTFI("} else {\n");
					indent_level++;
					OUTFI(basic_printers[i].standard, tcp, arg);
					OUTC('\n');
					indent_level--;
					OUTFI("}\n");
				} else {
					OUTFI(basic_printers[i].standard, tcp, arg);
					OUTC('\n');
				}
				return;
			}
		}
		outf_indent(indent_level, out, "#error UNHANDLED BASIC TYPE: %s\n", type->name);
	} else if (type->type == TYPE_PTR) {
		// special cases
		if (strcmp(type->ptr.type->name, "string") == 0) {
			generate_printer(ctx, out, tcp, arg, entering, type->ptr.type, indent_level);
		} else {
			if (IS_IN_PTR(type)) {
				static int counter;
				// copy from target memory and use decoder for resulting value
				char var_name[32];
				snprintf(var_name, 32, "tmpvar_%d", counter++);
				OUTFI("%s %s;\n", type_to_ctype(type->ptr.type), var_name);
				OUTFI("if (!umove_or_printaddr(%s, %s, &%s)) {\n ",
					  tcp, arg, var_name);

				generate_printer(ctx, out, tcp, var_name, entering, type->ptr.type,
								 indent_level + 1);

				OUTSI("}\n");
			}
			if (IS_OUT_PTR(type) && !entering) {
				char deref_arg[128];
				snprintf(deref_arg, 128, "(&(%s))", arg);

				generate_printer(ctx, out, tcp, deref_arg, entering, type->ptr.type, indent_level);
			}
		}
		return;
	} else {
		outf_indent(indent_level, out, "#error UNHANDLED TYPE: %s\n", type->name);
	}
}

static void
generate_decoder(struct codegen_ctx *ctx, FILE *out, struct ast_node *node, int indent_level)
{
	// determine which strategy to use depending on how many OUT ptrs there are
	size_t out_ptrs = 0;
	for (struct ast_syscall_arg *arg = node->syscall.args; arg != NULL; arg = arg->next) {
		if (IS_OUT_PTR(arg->type)) {
			out_ptrs++;
		}
	}

	OUTFI("SYS_FUNC(%s)\n", node->syscall.name);
	OUTS("{\n");
	indent_level++;

	int arg_index = 0;
	char arg_val[15];

	if (out_ptrs == 0) {
		// 0 out ptrs: print all args in sysenter
		for (struct ast_syscall_arg *arg = node->syscall.args; arg != NULL; arg = arg->next) {
			OUTFI("/* arg: %s (%s) */\n", arg->name, type_to_ctype(arg->type));
			snprintf(arg_val, 15, "tcp->u_arg[%d]", arg_index++);

			generate_printer(ctx, out, "tcp", arg_val, true, arg->type, indent_level);

			if (arg->next) {
				OUTSI("tprint_arg_next();\n");
			}
		}

		OUTSI("return RVAL_DECODED;\n");
	} else if (out_ptrs == 1) {
		// == 1 out ptrs: print args until the out ptr in sysenter, rest in sysexit
		struct ast_syscall_arg *cur = node->syscall.args;

		OUTSI("if (entering(tcp)) {\n");
		indent_level++;
		for (; cur != NULL && !IS_OUT_PTR(cur->type); cur = cur->next) {
			OUTFI("/* arg: %s (%s) */\n", cur->name, type_to_ctype(cur->type));
			snprintf(arg_val, 15, "tcp->u_arg[%d]", arg_index++);

			generate_printer(ctx, out, "tcp", arg_val, true, cur->type, indent_level);

			if (cur->next) {
				OUTSI("tprint_arg_next();\n");
			}
		}
		indent_level--;

		if (IS_INOUT_PTR(cur->type)) {
			// TODO: store the current value
		}

		indent_level++;
		OUTSI("return 0;\n");
		indent_level--;
		OUTSI("}\n");

		for (; cur != NULL; cur = cur->next) {
			OUTFI("/* arg: %s (%s) */\n", cur->name, type_to_ctype(cur->type));
			snprintf(arg_val, 15, "tcp->u_arg[%d]", arg_index++);

			generate_printer(ctx, out, "tcp", arg_val, false, cur->type, indent_level);

			if (cur->next) {
				OUTSI("tprint_arg_next();\n\n");
			}
		}

		OUTSI("return RVAL_DECODED;\n");
	} else {
		// > 1 out ptrs; store ptr values using set_tcb_priv_data
		// TODO:
		OUTSI("if (entering(tcp)) {\n");
		indent_level++;

		for (struct ast_syscall_arg *arg = node->syscall.args; arg != NULL; arg = arg->next) {
			OUTFI("/* arg: %s (%s) */\n", arg->name, type_to_ctype(arg->type));
			snprintf(arg_val, 15, "tcp->u_arg[%d]", arg_index++);

			generate_printer(ctx, out, "tcp", arg_val, true, arg->type, indent_level);
			OUTC('\n');
			OUTSI("tprint_arg_next();\n");
		}

		OUTS("#error TODO: \n");

		indent_level--;
	}

	indent_level--;
	OUTSI("}\n\n");
}

static void
visit_node(struct codegen_ctx *ctx, FILE *out, struct ast_node *node, int indent_level)
{
	outf_indent(indent_level, out, "// Debug Location: %s:%d:%d Node Type: ",
				ctx->in_filename, node->loc.lineno, node->loc.colno);

	switch (node->type) {
		case AST_INCLUDE: {
			OUTS("AST_INCLUDE\n");
			OUTC('#');
			OUTS(node->include.value);
			OUTC('\n');
			break;
		}
		case AST_DEFINE: {
			OUTS("AST_DEFINE\n");
			OUTS(node->define.value);
			OUTC('\n');
			break;
		}
		case AST_IFDEF: {
			OUTS("AST_IFDEF\n");
			OUTS(node->ifdef.value);
			OUTC('\n');
			visit_node(ctx, out, node->ifdef.child, indent_level);
			OUTS("#endif\n");
			break;
		}
		case AST_COMPOUND: {
			OUTS("AST_COMPOUND\n");
			for (struct ast_node *cur = node->compound.children; cur != NULL; cur = cur->next) {
				visit_node(ctx, out, cur, indent_level);
			}
			break;
		}
		case AST_SYSCALL: {
			OUTS("AST_SYSCALL\n");
			generate_decoder(ctx, out, node, indent_level);
			break;
		}
		case AST_STRUCT: {
			OUTS("AST_STRUCT\n");
			OUTF("struct %s {}\n", node->ast_struct.name);
			break;
		}
		case AST_FLAGS: {
			OUTS("AST_FLAGS\n");
		}
	}
}

bool
generate_code(char *in_filename, char *out_filename, struct ast_node *root)
{
	FILE *out = fopen(out_filename, "w");

	if (out == NULL) {
		return false;
	}

	outf(out, "/* AUTOMATICALLY GENERATED FROM %s - DO NOT EDIT */\n\n", in_filename);
	outf(out, "%s", "#include \"defs.h\"\n\n");

	struct codegen_ctx ctx = {
		.in_filename = in_filename
	};

	visit_node(&ctx, out, root, 0);

	fclose(out);

	return true;
}
