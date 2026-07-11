#include <ed2k/version.hpp>

int main() {
  return ed2k::version().empty() ? 1 : 0;
}
