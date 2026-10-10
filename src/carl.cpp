#include <carl/carl.hpp>
int main(int argc, char** argv) {
  carl::bootstrap();
  carl::orchestrator o;
  o.loop(argc, argv);
  return 0;
}
