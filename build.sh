docker run -i --rm -v ./src:/src -v ./dist:/dist gcc:latest g++ -pthread -o /dist/server /src/server.cpp
