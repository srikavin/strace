CFLAGS += -ggdb -std=gnu99 -Wall

all: parse

parse: parse.tab.o lex.yy.o ast.o codegen.o parse.tab.h lex.yy.c
	$(CC) $(CFLAGS) parse.tab.o lex.yy.o ast.o codegen.o -o ./parse -ll

lex.yy.c: lex.l parse.tab.h
	flex lex.l

parse.tab.c parse.tab.h: parse.y
	bison -d -v -t -Wcounterexamples parse.y

clean:
	rm -f lex.yy.o ast.o parse.tab.o codegen.o
	rm -f parse parse.tab.c parse.tab.h lex.yy.c lex.yy.h
