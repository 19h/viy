#include <stdint.h>

typedef uintptr_t (*transform_t)(uintptr_t);
static transform_t volatile observed_slots[2];

__attribute__((noinline)) static uintptr_t first(uintptr_t value)
{
  return value + 7;
}

__attribute__((noinline)) static uintptr_t second(uintptr_t value)
{
  return value ^ 23;
}

int main(int argc, char **argv)
{
  (void)argv;
  observed_slots[0] = first;
  observed_slots[1] = second;
  transform_t a = observed_slots[0];
  transform_t b = observed_slots[1];
  return (int)(a((uintptr_t)argc) + b((uintptr_t)argc));
}
