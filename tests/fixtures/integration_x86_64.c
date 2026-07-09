#include <stddef.h>
#include <stdint.h>

typedef uint64_t (*transform_t)(uint64_t);

static volatile uint64_t sink;
static volatile transform_t selected;
static volatile char runtime_text[32];

__attribute__((noinline)) static uint64_t add_bias(uint64_t value)
{
  return value + UINT64_C(0x1234);
}

__attribute__((noinline)) static uint64_t xor_bias(uint64_t value)
{
  return value ^ UINT64_C(0x55aa);
}

// Stable, analysis-oriented fixture shapes. The wrapper gives
// the read-only deobfuscation provider a deterministic one-call/return shape;
// the adjacent complementary branches give the native provider an exact local
// structural fact without relying on compiler optimization accidents.
__attribute__((noinline)) static uint64_t wrapper_bias(uint64_t value)
{
  return add_bias(value);
}

__attribute__((noinline)) static int native_opposite_branches(int value)
{
  __asm__ volatile(
      "testl %0, %0\n\t"
      "je 1f\n\t"
      "jne 1f\n\t"
      "nop\n"
      "1:"
      : : "r"(value) : "cc");
  return value;
}

__attribute__((noinline)) static void construct_text(uint64_t selector)
{
  static const char first[] = "worker";
  static const char second[] = "evidence";
  const char *source = selector != 0 ? first : second;
  size_t index = 0;
  do
  {
    runtime_text[index] = source[index];
  }
  while ( source[index++] != '\0' );
}

int main(int argc, char **argv)
{
  (void)argv;
  selected = argc > 1 ? xor_bias : add_bias;
  sink = selected((uint64_t)(unsigned)argc); // intentional indirect call
  sink ^= wrapper_bias((uint64_t)(unsigned)argc);
  sink ^= (uint64_t)(unsigned)native_opposite_branches(argc);
  construct_text((uint64_t)(unsigned)argc);
  return (int)(sink & 0x7f);
}
