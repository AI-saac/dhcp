SERVER_TARGET=mydhcpd
CLIENT_TARGET=mydhcpc

SERVER_SRC=server.c msg.c sock_util.c
CLIENT_SRC=client.c msg.c sock_util.c

SERVER_DOT=server-diagram.dot
SERVER_PDF=server-diagram.pdf
CLIENT_DOT=client-diagram.dot
CLIENT_PDF=client-diagram.pdf

CC=gcc

all: $(SERVER_TARGET) $(CLIENT_TARGET)

$(SERVER_TARGET): $(SERVER_SRC)
	$(CC)  -o $@ $^

$(CLIENT_TARGET): $(CLIENT_SRC)
	$(CC)  -o $@ $^

$(SERVER_PDF): $(SERVER_DOT)
	dot -Tpdf $< -o $@

$(CLIENT_PDF): $(CLIENT_DOT)
	dot -Tpdf $< -o $@

pdf: $(SERVER_PDF) $(CLIENT_PDF)

