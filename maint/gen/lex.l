%option noyywrap yylineno nodefault warn
/* %option debug */

%{
#include <stdio.h>
#include <stdint.h>
#include "deflang.h"
#include "ast.h"
#include "parse.tab.h"

YYSTYPE yylval;
YYLTYPE yylloc;

static void
update_yylloc();

#define YY_USER_ACTION update_yylloc();

#define MAX_IMPORT_LEVEL 10

struct saved_import_state {
	YYLTYPE location;
	char *filename;
	int cur_location;
	int last_line_location;
};

// a stack to store state before an import
static struct saved_import_state import_states[MAX_IMPORT_LEVEL];
// the current index into import_states
static int import_level = 0;

char *cur_filename;

static int cur_location;

int last_line_location;
%}

%x COMMENT_MULTI
%x COMMENT_LINE
%x IMPORT

%%
"," return T_COMMA;
"(" return T_LPAREN;
")" return T_RPAREN;
"[" return T_LBRACKET;
"]" return T_RBRACKET;
"{" return T_LCURLY;
"}" return T_RCURLY;
"=" return T_EQUALS;
":" return T_COLON;

(-)?"0x"[0-9A-Fa-f]+ {
	yylval.number.raw = strdup(yytext);
	yylval.number.val = strtol(yytext, NULL, 16);
	return T_NUMBER;
}

(-)?[0-9]+ {
	yylval.number.raw = strdup(yytext);
	yylval.number.val = strtol(yytext, NULL, 10);
	return T_NUMBER;
}

[A-Za-z_][A-Za-z0-9_\$]* {
	yylval.str = strdup(yytext);
	return T_IDENTIFIER;
}

"define".+ {
	yylval.str = strdup(yytext);
	return T_DEFINE;
}
"#ifdef".+ {
	yylval.str = strdup(yytext);
	return T_IFDEF;
}
"#ifndef".+ {
	yylval.str = strdup(yytext);
	return T_IFNDEF;
}
"include".+ {
	yylval.str = strdup(yytext);
	return T_INCLUDE;
}
"#endif".* {
	return T_ENDIF;
}

"#import \"" {
	BEGIN(IMPORT);
}
<IMPORT>[^\n\"]+ {
	if (import_level >= MAX_IMPORT_LEVEL) {
		fprintf(stderr, "imports are nested more than %d levels\n", MAX_IMPORT_LEVEL);
		yyterminate();
	}

	// eat characters until newline
	int c = input();
	cur_location++;
	while(c && c != '\n'){
		cur_location++;
		c = input();
	}
	// update current location
	yylloc.last_line++;
	yylloc.last_column = 1;
	last_line_location = cur_location;

	// save current state
	import_states[import_level++] = (struct saved_import_state) {
		.filename = cur_filename,
		.location = yylloc,
		.cur_location = cur_location,
		.last_line_location = last_line_location
	};

	cur_filename = strdup(yytext);

	yylloc = (struct YYLTYPE) {1, 1, 1, 1};
	cur_location = 0;
	last_line_location = 0;

	yyin = fopen(yytext, "r");

	if (yyin == NULL) {
		fprintf(stderr, "failed to import file '%s' on line %d\n", yytext, yylineno);
		yyterminate();
	}

	yypush_buffer_state(yy_create_buffer(yyin, YY_BUF_SIZE));
	BEGIN(INITIAL);
}

<<EOF>> {
	// emit a newline at the end of a file before EOF
	// to ensure the last statement in the file is terminated
	static int emitted_newline;

	if (!emitted_newline) {
		emitted_newline = 1;
		return T_NEWLINE;
	}

	emitted_newline = 0;

	if (import_level > 0) {
		free(cur_filename);

		struct saved_import_state saved = import_states[--import_level];

		cur_filename = saved.filename;
		cur_location = saved.cur_location;
		last_line_location = saved.last_line_location;
		yylloc = saved.location;
	}
	yypop_buffer_state();
	if (!YY_CURRENT_BUFFER) {
		yyterminate();
	}
}

"/*" {
	BEGIN(COMMENT_MULTI);
}
<COMMENT_MULTI>"*/" {
	BEGIN(INITIAL);
}

"//"|"#" {
	BEGIN(COMMENT_LINE);
}
<COMMENT_LINE>\n {
	BEGIN(INITIAL);
}

<COMMENT_LINE,COMMENT_MULTI>. {}

[ \t\r] {}

\n {
	return T_NEWLINE;
}

. {
	yyerror("unexpected character: %s", yytext);
	yyterminate();
}

%%

static void
update_yylloc()
{
	yylloc.first_line = yylloc.last_line;
	yylloc.first_column = yylloc.last_column;

	int i = 0;
	while (yytext[i] != '\0') {
		cur_location++;
		if (yytext[i] == '\n') {
			yylloc.last_line++;
			yylloc.last_column = 1;
			last_line_location = cur_location;
		} else {
			yylloc.last_column++;
		}
		i++;
	}
}

bool
lexer_init_newfile(char *filename)
{
	// clean up internal state managed by flex
	yylex_destroy();

	yyin = fopen(filename, "r");
	if (yyin == NULL) {
		return false;
	}

	cur_filename = filename;

	return true;
}