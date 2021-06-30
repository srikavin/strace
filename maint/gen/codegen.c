#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "ast.h"
#include "deflang.h"
#include "symbols.h"

struct basic_printer {
	char *type;
	char *standard;
	char *generic;
};

/*
 * This is necessary since positional fmt arguments can't skip indices. This macro
 * ensures that all arguments' types are specified without affecting the output.
 */
#define BASIC_FMT(fmt) (fmt "%1$.0s" "%2$.0s")

struct basic_printer basic_printers[] = {
	// %1$s is tcp, %2$s is the argument value, %3$s is the argument index
	{"fd", BASIC_FMT("printfd(%1$s, %2$s);"), NULL},
	{"uid", BASIC_FMT("printuid(%2$s);"), NULL},
	{"gid", BASIC_FMT("printuid(%2$s);"), NULL},
};

struct basic_printer ptr_special_printers[] = {
	{"string", BASIC_FMT("printstr(%1$s, %2$s);"), BASIC_FMT("printaddr(%2$s);")},
	{"path", BASIC_FMT("printpath(%1$s, %2$s);"), BASIC_FMT("printaddr(%2$s);")}
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
	{"path", "char"},
	{"size", "kernel_size_t"},
	{"size_t", "kernel_size_t"},
	{"gid", "gid_t"}
};

char *signed_int_types[] = {
	"char",
	"short",
	"int",
	"long",
	"longlong",
	"kernel_long_t",
	"ssize_t"
};

char *unsigned_int_types[] = {
	"uchar",
	"ushort",
	"uint",
	"ulong",
	"ulonglong",
	"kernel_ulong_t",
	"size_t",
	"size"
};

#define ARRAY_LEN(x) (sizeof(x) / sizeof((x)[0]))

/* convenience macros */

#define OUTFI(...) outf_indent(indent_level, out, __VA_ARGS__)

#define OUTF(...) outf(out, __VA_ARGS__)

#define OUTC(c) outc(out, c)

#define OUTSI(s) outs_indent(indent_level, out, s)

#define OUTS(s) outs(out, s)

static void
outf_indent(int indent_level, FILE *out, const char *fmt,
			...) __attribute__((format(printf, 3, 4)));

static void
outf(FILE *out, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

static void
outc(FILE *out, int c)
{
	fputc(c, out);
}

static void
outs(FILE *out, const char *s)
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
outs_indent(int indent_level, FILE *out, const char *s)
{
	indent(out, indent_level);
	fprintf(out, "%s", s);
}

static void
outf(FILE *out, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);

	vfprintf(out, fmt, args);

	va_end(args);
}

static void
outf_indent(int indent_level, FILE *out, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);

	indent(out, indent_level);
	vfprintf(out, fmt, args);

	va_end(args);
}

struct codegen_ctx {
	const char *in_filename;
};

static void
log_warning(char *fmt, struct ast_node *node, ...)
{
	va_list args;
	va_start(args, node);

	fprintf(stderr, "Codegen Warning: ");
	if (node) {
		fprintf(stderr, "line %d, col %d: ", node->loc.lineno, node->loc.colno);
	}

	vfprintf(stderr, fmt, args);

	fprintf(stderr, "\n");

	va_end(args);
}

static bool
is_signed_integer_typename(const char *name)
{
	for (size_t i = 0; i < ARRAY_LEN(signed_int_types); ++i) {
		if (strcmp(signed_int_types[i], name) == 0) {
			return true;
		}
	}

	return false;
}

static bool
is_unsigned_integer_typename(const char *name)
{
	for (size_t i = 0; i < ARRAY_LEN(unsigned_int_types); ++i) {
		if (strcmp(unsigned_int_types[i], name) == 0) {
			return true;
		}
	}

	return false;
}

/*
 * Stores a string referring to the i-th argument in the current syscall.
 */
static void
get_syscall_arg_value(char out[static 16], const char *tcp, size_t i)
{
	snprintf(out, 16, "(%s)->u_arg[%zu]", tcp, i);
}

/*
 * Stores a string referring to the return value of the current syscall.
 */
static void
get_syscall_ret_value(char out[static 16], const char *tcp)
{
	snprintf(out, 16, "(%s)->u_rval", tcp);
}

/*
 * Converts a string containing the C equivalent of a given type.
 */
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

		size_t len = strlen(underlying) + sizeof(" *");
		char *ret = xmalloc(len);
		snprintf(ret, len, "%s *", underlying);
		return ret;
	}

	return type->name;
}

/*
 * Get flags to return from a SYS_FUNC.
 */
static void
get_sys_func_return_flags(char out[static 64], struct ast_type *type, bool is_ioctl)
{
	struct {
		char *type;
		char *flag;
	} flags[] = {
		{"fd", "RVAL_FD"},
		{"tid", "RVAL_TID"},
		{"sid", "RVAL_SID"},
		{"tgid", "RVAL_TGID"},
		{"pgid", "RVAL_PGID"}
	};

	char *base = "RVAL_DECODED";
	if (is_ioctl) {
		base = "RVAL_IOCTL_DECODED";
	}

	char *following = NULL;
	for (size_t i = 0; i < ARRAY_LEN(flags); ++i) {
		if (strcmp(flags[i].type, type->name) == 0) {
			following = flags[i].flag;
			break;
		}
	}

	if (following) {
		snprintf(out, 64, "%s | %s", base, following);
	} else {
		snprintf(out, 64, "%s", base);
	}
}

/*
 * Resolves a type option to a concrete value.
 *
 * For example, const[PATH_MAX] is resolved to PATH_MAX
 * and const[ref[argname]] is resolved to tcp->u_arg[2]
 * (where argname is the name of the 3rd syscall argument).
 *
 * The specified type option MUST NOT be a range.
 */
static char *
resolve_type_option_to_value(struct ast_node *node, struct ast_type_option *option)
{
	assert(option->type != AST_TYPE_CHILD_RANGE);

	if (option->child_type == AST_TYPE_CHILD_NUMBER) {
		// return the number exactly as specified in the source file
		return option->number.raw;
	} else if (option->child_type == AST_TYPE_CHILD_TYPE) {
		if (option->type->type == TYPE_REF) {
			// identify which argument is being referred to

			// syscall return value
			if (option->type->ref.return_value) {
				char *ret = xmalloc(16);
				get_syscall_ret_value(ret, "tcp");
				return ret;
			}

			// find syscall argument by name
			bool found = false;
			size_t index = 0;

			for (struct ast_syscall_arg *cur = node->syscall.args; cur != NULL; cur = cur->next) {
				if (strcmp(option->type->ref.argname, cur->name) == 0) {
					found = true;
					break;
				}
				index++;
			}

			if (found) {
				char *ret = xmalloc(16);
				get_syscall_arg_value(ret, "tcp", index);
				return ret;
			}

			log_warning("Failed to resolve 'ref' type with value \"%s\" to argument",
						node, option->type->ref.argname);
			return "#error FAILED TO RESOLVE REF TYPE TO VALUE";
		} else {
			// assume the given value is a constant or from a #define
			return option->type->name;
		}
	}

	assert(false);
}

/*
 * Stores the value of a given variable using set_tcb_priv_data.
 */
static void
store_single_value(FILE *out, struct ast_type *type, char *arg, int indent_level)
{
	OUTFI("{\n");
	indent_level++;

	OUTFI("%s %s;\n", type_to_ctype(type->ptr.type), "tmp_var");
	OUTFI("if (!umove_or_printaddr(tcp, %s, &tmp_var)) {\n", arg);
	indent_level++;

	OUTFI("void *tmp_buffer = xmalloc(sizeof(%s));\n", type_to_ctype(type->ptr.type));
	OUTFI("set_tcb_priv_data(tcp, tmp_buffer, free);\n");

	indent_level--;
	OUTFI("}\n");

	indent_level--;
	OUTFI("}\n");
}

static void
generate_generic_printer(FILE *out, const char *tcp, const char *arg, bool entering,
						 const char *standard, const char *generic, int indent_level)
{
	if (!entering && generic) {
		OUTFI("if (syserror(%s)) {\n", tcp);
		indent_level++;

		OUTFI(generic, tcp, arg);
		OUTC('\n');
		indent_level--;
		OUTFI("} else {\n");
		indent_level++;
		OUTFI(standard, tcp, arg);
		OUTC('\n');
		indent_level--;
		OUTFI("}\n");
	} else {
		OUTFI(standard, tcp, arg);
		OUTC('\n');
	}
}

static void
generate_basic_printer(FILE *out, const char *tcp, const char *arg, bool entering,
					   struct basic_printer printer, int indent_level)
{
	generate_generic_printer(out, tcp, arg, entering,
							 printer.standard, printer.generic, indent_level);
}

static void
generate_printer(struct codegen_ctx *ctx, FILE *out, struct ast_node *node,
				 const char *argname, const char *tcp, const char *arg, bool entering,
				 struct ast_type *type, int indent_level);

static void
generate_printer_ptr(struct codegen_ctx *ctx, FILE *out, struct ast_node *node,
					 const char *argname, const char *tcp, const char *arg, bool entering,
					 struct ast_type *type, int indent_level)
{
	struct ast_type *underlying = type->ptr.type;

	// strings and arrays are already pointer types in C,
	// so we need a special case to handle them
	for (size_t i = 0; i < ARRAY_LEN(ptr_special_printers); ++i) {
		if (strcmp(underlying->name, ptr_special_printers[i].type) == 0) {
			generate_basic_printer(out, tcp, arg, entering, ptr_special_printers[i], indent_level);
			return;
		}
	}

	if (underlying->type == TYPE_STRINGNOZ) {
		if (IS_OUT_PTR(type)) {
			OUTFI("if (syserror(%s)) {\n", tcp);
			OUTFI("\tprintaddr(%s);\n", arg);
			OUTFI("} else {\n");
			OUTFI("\tprintstrn(%s, %s, %s);\n", tcp, arg,
				  resolve_type_option_to_value(node, underlying->stringnoz.len));
			OUTFI("}\n");
		} else {
			OUTFI("printstrn(%s, %s, %s);\n", tcp, arg,
				  resolve_type_option_to_value(node, underlying->stringnoz.len));
		}
	} else {
		// copy from target memory and use decoder for resulting value
		char var_name[32];
		snprintf(var_name, 32, "tmpvar_%s", argname);

		if ((IS_IN_PTR(type) && entering) || (IS_OUT_PTR(type) && !entering)) {
			OUTFI("%s %s;\n", type_to_ctype(type->ptr.type), var_name);
			OUTFI("if (!umove_or_printaddr(%s, %s, &%s)) {\n ",
				  tcp, arg, var_name);

			generate_printer(ctx, out, node, argname, tcp, var_name, entering, type->ptr.type,
							 indent_level + 1);

			OUTSI("}\n");
		}
	}
}

/*
 * Outputs a call to a function/macro to print out arg with the given type.
 */
static void
generate_printer(struct codegen_ctx *ctx, FILE *out, struct ast_node *node,
				 const char *argname, const char *tcp, const char *arg, bool entering,
				 struct ast_type *type, int indent_level)
{
	if (type->type == TYPE_BASIC) {
		if (is_signed_integer_typename(type->name)) {
			OUTFI("PRINT_VAL_D((%s) %s);\n", type_to_ctype(type), arg);
			return;
		} else if (is_unsigned_integer_typename(type->name)) {
			OUTFI("PRINT_VAL_U((%s) %s);\n", type_to_ctype(type), arg);
			return;
		}

		for (size_t i = 0; i < ARRAY_LEN(basic_printers); ++i) {
			if (strcmp(type->name, basic_printers[i].type) == 0) {
				struct basic_printer cur = basic_printers[i];
				generate_basic_printer(out, tcp, arg, entering, cur, indent_level);
				return;
			}
		}

		log_warning("No known printer for basic type %s", node, type->name);
		outf_indent(indent_level, out, "#error UNHANDLED BASIC TYPE: %s\n", type->name);
	} else if (type->type == TYPE_PTR) {
		generate_printer_ptr(ctx, out, node, argname, tcp, arg, entering, type, indent_level);
	} else if (type->type == TYPE_ORFLAGS) {
		OUTFI("printflags(%s, %s, \"%s\");\n", type->orflags.flag_type->type->name, arg,
			  type->orflags.dflt);
	} else if (type->type == TYPE_XORFLAGS) {
		OUTFI("printxval(%s, %s, \"%s\");\n", type->xorflags.flag_type->type->name, arg,
			  type->orflags.dflt);
	} else if (type->type == TYPE_IGNORE) {
		// do nothing
	} else if (type->type == TYPE_STRINGNOZ || strcmp(type->name, "string") == 0) {
		log_warning("Type '%s' should be wrapped in a ptr type to indicate direction",
					node, type->name);
	} else {
		log_warning("Type '%s' is currently unhandled", node, type->name);
		outf_indent(indent_level, out, "#error UNHANDLED TYPE: %s\n", type->name);
	}
}

/*
 * Prints out a decoder for the given system call.
 */
static void
generate_decoder(struct codegen_ctx *ctx, FILE *out, struct ast_node *node)
{
	int indent_level = 0;

	// determine which strategy to use depending on how many OUT ptrs there are
	size_t out_ptrs = 0;
	for (struct ast_syscall_arg *arg = node->syscall.args; arg != NULL; arg = arg->next) {
		if (IS_OUT_PTR(arg->type)) {
			out_ptrs++;
		}
	}

	OUTFI("SYS_FUNC(%s)\n", node->syscall.name);
	OUTSI("{\n");
	indent_level++;

	int arg_index = 0;
	char arg_val[16];

	if (out_ptrs == 0) {
		// 0 out ptrs: print all args in sysenter
		for (struct ast_syscall_arg *arg = node->syscall.args; arg != NULL; arg = arg->next) {
			OUTFI("/* arg: %s (%s) */\n", arg->name, type_to_ctype(arg->type));
			get_syscall_arg_value(arg_val, "tcp", arg_index++);

			generate_printer(ctx, out, node, arg->name, "tcp", arg_val, true, arg->type,
							 indent_level);

			if (arg->next) {
				OUTSI("tprint_arg_next();\n");
			}
			OUTC('\n');
		}
	} else if (out_ptrs == 1) {
		// == 1 out ptrs: print args until the out ptr in sysenter, rest in sysexit
		struct ast_syscall_arg *cur = node->syscall.args;

		OUTSI("if (entering(tcp)) {\n");
		indent_level++;
		for (; cur != NULL && !IS_OUT_PTR(cur->type); cur = cur->next) {
			OUTFI("/* arg: %s (%s) */\n", cur->name, type_to_ctype(cur->type));
			get_syscall_arg_value(arg_val, "tcp", arg_index++);

			generate_printer(ctx, out, node, cur->name, "tcp", arg_val, true, cur->type,
							 indent_level);

			if (cur->next) {
				OUTSI("tprint_arg_next();\n\n");
			}
		}

		if (IS_INOUT_PTR(cur->type)) {
			store_single_value(out, cur->type, arg_val, indent_level);
		}

		OUTSI("return 0;\n");
		indent_level--;
		OUTSI("}\n");

		if (IS_INOUT_PTR(cur->type)) {
			// TODO: compare the current value with the previous value
			//		 and print only if changed
		}

		for (; cur != NULL; cur = cur->next) {
			OUTFI("/* arg: %s (%s) */\n", cur->name, type_to_ctype(cur->type));
			get_syscall_arg_value(arg_val, "tcp", arg_index++);

			generate_printer(ctx, out, node, cur->name, "tcp", arg_val, false, cur->type,
							 indent_level);

			if (cur->next) {
				OUTSI("tprint_arg_next();\n");
			}
			OUTC('\n');
		}
	} else {
		// TODO: > 1 out ptrs; store necessary ptr values using set_tcb_priv_data
		OUTSI("#error TODO\n");
	}

	char ret_flags[64];
	get_sys_func_return_flags(ret_flags, node->syscall.return_type, false);
	OUTFI("return %s;\n", ret_flags);

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
			generate_decoder(ctx, out, node);
			break;
		}
		case AST_STRUCT: {
			OUTS("AST_STRUCT\n");
			OUTF("static void\ngen_print_%s() {}\n", node->ast_struct.name);
			break;
		}
		case AST_FLAGS: {
			OUTS("AST_FLAGS\n");
			break;
		}
	}
}

bool
generate_code(const char *in_filename, const char *out_filename, struct ast_node *root)
{
	FILE *out = fopen(out_filename, "w");

	if (out == NULL) {
		return false;
	}

	outf(out, "/* AUTOMATICALLY GENERATED FROM %s - DO NOT EDIT */\n\n", in_filename);
	outf(out, "%s",
		 "#include <stddef.h>\n"
		 "#include \"defs.h\"\n\n"
		 "typedef kernel_ulong_t kernel_size_t;\n\n"
	);

	struct codegen_ctx ctx = {
		.in_filename = in_filename
	};

	visit_node(&ctx, out, root, 0);

	fclose(out);

	return true;
}
