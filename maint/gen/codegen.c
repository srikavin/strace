#include <stdarg.h>
#include <stdio.h>

#include "deflang.h"

static void
outf_indent(int indent_level, FILE *out, char *fmt, ...) __attribute__((format(printf, 3, 4)));

static void
outf(FILE *out, char *fmt, ...) __attribute__((format(printf, 2, 3)));

struct codegen_ctx {
    char *in_filename;
};

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
outs_indent(int indent_level, FILE *out, char *s)
{
    if (indent_level > 0) {
        fprintf(out, "%*s", indent_level, "\t");
    }
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

    if (indent_level > 0) {
        fprintf(out, "%*s", indent_level, "\t");
    }
    vfprintf(out, fmt, args);

    va_end(args);
}

static void
visit_node(struct codegen_ctx *ctx, FILE *out, struct ast_node *node, int indent_level)
{
    outf_indent(indent_level, out, "// Debug Location: %s:%d:%d Node Type: ",
        ctx->in_filename, node->loc.lineno, node->loc.colno);

    switch (node->type) {
        case AST_INCLUDE:
        {
            outs(out, "AST_INCLUDE\n");
            outc(out, '#');
            outs(out, node->include.value);
            outc(out, '\n');
            break;
        }
        case AST_DEFINE:
        {
            outs(out, "AST_DEFINE\n");
            outs(out, node->define.value);
            outc(out, '\n');
            break;
        }
        case AST_IFDEF:
        {
            outs(out, "AST_IFDEF\n");
            outs(out, node->ifdef.value);
            outc(out, '\n');
            visit_node(ctx, out, node->ifdef.child, indent_level);
            outs(out, "#endif\n");
            break;
        }
        case AST_COMPOUND:
        {
            outs(out, "AST_COMPOUND\n");
            for (struct ast_node *cur = node->compound.children; cur != NULL; cur = cur->next) {
                visit_node(ctx, out, cur, indent_level);
            }
            break;
        }
        case AST_SYSCALL:
        {
            outs(out, "AST_SYSCALL\n");
            outf_indent(indent_level, out, "int syscall_%s (void) {}\n", node->syscall.name);
            break;
        }
        case AST_STRUCT:
        {
            outs(out, "AST_STRUCT\n");
            outf(out, "struct %s {}\n", node->ast_struct.name);
            break;
        }
        case AST_FLAGS:
        {
            outs(out, "AST_FLAGS\n");
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

    outf(out, "/* AUTOMATICALLY GENERATED from %s - DO NOT EDIT */\n\n", in_filename);

    struct codegen_ctx ctx = {
        .in_filename = in_filename
    };

    visit_node(&ctx, out, root, 0);

    return true;
}
