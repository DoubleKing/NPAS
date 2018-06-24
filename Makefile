INC_DIR:= ./include/
SRC_DIR:= ./src/
SRCS:=$(wildcard ./src/*.c)
LIBS:= -lpcap
CXX:= gcc
CXXFLAGS:=-Wall -g $(addprefix -I, $(INC_DIR)) $(LIBS) -Wno-unused-function

EXE:=./bin/npas

$(EXE):$(SRCS)
	$(CXX) -o $@ $(SRCS) $(CXXFLAGS)
clean:
	rm -rf $(EXE)
