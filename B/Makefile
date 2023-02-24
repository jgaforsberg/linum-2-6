CC=gcc
FIL=checkuser.c
OPT=-o
LIB=-lpam -lpam_misc
EXE=checkuser
SRC=./src/
DIR=/usr/local/bin/

all: $(EXE)

$(EXE): $(SRC)$(FIL)
	$(CC) $(OPT) $(EXE) $(SRC)$(FIL) $(LIB)

B1: $(SRC)$(FIL)
	$(CC) $(OPT) $(DIR)$(EXE) $(SRC)$(FIL) $(LIB)
	cp -f B1/checkuser /etc/pam.d

B2: $(SRC)$(FIL)
	$(CC) $(OPT) $(DIR)$(EXE) $(SRC)$(FIL) $(LIB)
	cp -f ./B2/checkuser /etc/pam.d && cp -f ./B2/checkuser.conf /etc/security

B3: $(SRC)$(FIL)
	$(CC) $(OPT) $(DIR)$(EXE) $(SRC)$(FIL) $(LIB)
	cp -f ./B3/checkuser /etc/pam.d && cp -f ./B3/checkuser.conf /etc/security

clean:
	rm -rf $(EXE)

install:
	cp $(EXE) $(DIR)

uninstall:
	rm -rf $(DIR)$(EXE) /etc/pam.d/checkuser /etc/security/checkuser.conf


