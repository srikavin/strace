#include <stdbool.h>
#include <stdio.h>

#include "ast.h"

extern int yylineno;
extern FILE* yyin;

extern int last_line_location;
extern char *cur_filename;

extern int
yylex_destroy(void);

bool
lexer_init_newfile(char *filename);

void
yyerror(const char *s, ...) __attribute__ ((format (printf, 1, 2)));

bool
generate_code(char *in_filename, char *out_filename, struct ast_node *root);