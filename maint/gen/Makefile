CFLAGS += -ggdb -std=gnu99 -Wall -fsanitize=address

all: parse

parse: parse.tab.o lex.yy.o ast.o codegen.o symbols.o parse.tab.h lex.yy.c
	$(CC) $(CFLAGS) parse.tab.o lex.yy.o ast.o codegen.o symbols.o -o ./parse -ll

lex.yy.c: lex.l parse.tab.h
	flex lex.l

parse.tab.c parse.tab.h: parse.y
	bison -d parse.y

clean:
	rm -f lex.yy.o ast.o parse.tab.o codegen.o preprocess.o symbols.o
	rm -f parse parse.tab.c parse.tab.h lex.yy.c lex.yy.h
