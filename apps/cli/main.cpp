#include "ed2k/version.hpp"
#include <cstdio>
int main() { std::printf("ed2k-tool %s\n", ed2k::version().data()); return 0; }
