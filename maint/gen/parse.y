%define api.token.prefix {T_}
%define parse.lac full
%define parse.error detailed

%locations

%code requires {
#include "deflang.h"
#include "ast.h"
}

%{
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct ast_node *root;
%}

%union {
	char* str;
	struct ast_number number;

	struct ast_node *node;
	struct ast_type *type;
	struct ast_type_option *type_option;
	struct ast_type_option_list *type_option_list;
	struct ast_syscall_arg *syscall_arg;
	struct ast_struct_element *struct_element;
	struct ast_flag_values *flag_values;
}

%token NEWLINE
%token LPAREN "("
%token RPAREN ")"
%token LBRACKET "["
%token RBRACKET "]"
%token LCURLY "{"
%token RCURLY "}"
%token COMMA ","
%token EQUALS "="
%token <str> DEFINE "#define"
%token <str> IFDEF "#ifdef"
%token ENDIF "#endif"
%token <str> IFNDEF "#ifndef"
%token <str> INCLUDE "include"
%token <str> IDENTIFIER;
%token <number> NUMBER;

%type <node> compound compound_stmt statement define ifdef ifndef include syscall struct flags
%type <type> type syscall_return_type
%type <type_option_list> type_options
%type <type_option> type_option
%type <syscall_arg> syscall_arglist syscall_arg
%type <struct_element> struct_element struct_elements
%type <flag_values> flag_elements

%destructor { free($$); } <str>
%destructor { free($$.raw); } <number>
%destructor { free_ast_tree($$); } <node>

%start start

%%

start: opt_linebreak compound_stmt
		{
			root = $2;
		}

opt_linebreak: linebreaks | %empty

linebreaks: NEWLINE linebreaks
	| NEWLINE

compound: linebreaks compound_stmt
		{
			$$ = $2;
		}

compound_stmt: statement linebreaks compound_stmt
		{
			$1->next = $3->compound.children;
			$3->compound.children = $1;
			$$ = $3;
		}
	| statement linebreaks
		{
			$$ = create_ast_node(AST_COMPOUND, &@$);
			$$->compound.children = $1;
		}

statement: define
	| ifdef
	| ifndef
	| include
	| syscall
	| struct
	| flags

syscall: IDENTIFIER "(" syscall_arglist ")" syscall_return_type syscall_attribute
		{
			$$ = create_ast_node(AST_SYSCALL, &@$);
			$$->syscall = (struct ast_syscall) {
				.name = $1,
				.args = $3,
				.return_type = $5
			};
		}

syscall_return_type: type
		{
			$$ = $1;
		}
	| %empty
		{
			$$ = NULL;
		}

syscall_attribute: "(" type_options ")"
	| %empty

syscall_arglist: syscall_arg
		{
			$$ = $1;
		}
	| syscall_arg "," syscall_arglist
		{
			$$ = $1;
			$1->next = $3;
		}

syscall_arg: IDENTIFIER type
		{
			$$ = create_ast_syscall_arg($1, $2, NULL);;
		}

type: IDENTIFIER
		{
			$$ = create_or_get_type($1, NULL);
		}
	| IDENTIFIER "[" type_options "]"
		{
			$$ = create_or_get_type($1, $3);
		}

type_options: type_option "," type_options
		{
			$$ = create_ast_type_option_list($1, $3);
		}
	| type_option
		{
			$$ = create_ast_type_option_list($1, NULL);
		}

type_option: type
		{
			$$ = create_or_get_type_option_nested($1);
		}
	| NUMBER
		{
			$$ = create_or_get_type_option_number($1);
		}

define: DEFINE
		{
		   $$ = create_ast_node(AST_DEFINE, &@$);
		   $$->define.value = $1;
		}

ifdef: IFDEF compound ENDIF
		{
			$$ = create_ast_node(AST_IFDEF, &@$);
			$$->ifdef.value = $1;
			$$->ifdef.invert = false;
			$$->ifdef.child = $2;
		}

ifndef: IFNDEF compound ENDIF
		{
			$$ = create_ast_node(AST_IFDEF, &@$);
			$$->ifdef.value = $1;
			$$->ifdef.invert = true;
			$$->ifdef.child = $2;
		}

include: INCLUDE
		{
			$$ = create_ast_node(AST_INCLUDE, &@$);
			$$->include.value = $1;
		}

struct: IDENTIFIER "{" linebreaks struct_elements "}" struct_attr
		{
			$$ = create_ast_node(AST_STRUCT, &@$);
			$$->ast_struct.name = $1;
			$$->ast_struct.elements = $4;
		}
	| IDENTIFIER "{" linebreaks "}" struct_attr
		{
			yyerror("struct '%s' has no members", $1);
			$$ = NULL;
			YYERROR;
		}

struct_elements: struct_element struct_elements
		{
			$$ = $1;
			$$->next = $2;
		}
	| struct_element
		{
			$$ = $1;
		}

struct_element: IDENTIFIER type linebreaks
		{
			$$ = create_ast_struct_element($1, $2, NULL);
		}

struct_attr: "[" type "]"
	| %empty

flags: IDENTIFIER "=" flag_elements
		{
			$$ = create_ast_node(AST_FLAGS, &@$);
			$$->flags.name = $1;
		}

flag_elements: IDENTIFIER "," flag_elements
		{
			$$ = create_ast_flag_values($1, $3);
		}
	| IDENTIFIER
		{
			$$ = create_ast_flag_values($1, NULL);
		}

%%

void
yyerror (const char* fmt, ...)
{
	char buffer[257] = {0};

	long int saved = ftell(yyin);
	fseek(yyin, last_line_location, SEEK_SET);
	fgets(buffer, 256, yyin);
	fseek(yyin, saved, SEEK_SET);

	// add a new line if necessary
	size_t len = strlen(buffer);
	if (buffer[len - 1] != '\n') {
		buffer[len] = '\n';
		buffer[len + 1] = '\0';
	}

	va_list args;
	va_start(args, fmt);

	fprintf(stderr, "error %d: %s: line %d column %d\n", yynerrs, cur_filename,
			yylloc.first_line, yylloc.first_column);
	fprintf(stderr, "\t%s", buffer);
	fprintf(stderr, "\t%*s ", yylloc.first_column, "^");
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");

	va_end(args);
}

int
main(int argc, char **argv)
{
	yydebug = 0;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s [input files ...]\n", argv[0]);
		return EXIT_FAILURE;
	}

	bool failure = false;
	for(int i = 1; i < argc; ++i){

		if (!lexer_init_newfile(argv[i])){
			failure = true;
			continue;
		}

		if (yyparse() != 0) {
			failure = true;
			continue;
		}

		if (!generate_code(argv[i], "test.c", root)) {
			failure = true;
			free_ast_tree(root);
			continue;
		}

		free_ast_tree(root);
	}

	return failure;
}