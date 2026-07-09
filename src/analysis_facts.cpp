#include "analysis_facts.hpp"

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <limits>
#include <sstream>
#include <tuple>
#include <type_traits>
#include <utility>

namespace viy {
namespace analysis {
namespace {

constexpr uint16_t kCodecVersion = 1;
constexpr uint8_t kPayloadMagic[4] = {'V', 'I', 'Y', 'P'};
constexpr uint8_t kEvidenceMagic[4] = {'V', 'I', 'Y', 'E'};
constexpr uint8_t kFactMagic[4] = {'V', 'I', 'Y', 'F'};

bool fail(std::string *error, const std::string &message)
{
  if (error != nullptr)
    *error = message;
  return false;
}

template <typename Enum>
bool enum_between(Enum value, Enum first, Enum last)
{
  using U = typename std::underlying_type<Enum>::type;
  const U v = static_cast<U>(value);
  return v >= static_cast<U>(first) && v <= static_cast<U>(last);
}

template <typename>
struct always_false : std::false_type {};

bool range_valid(Address start, Address end)
{
  return start < end;
}

bool sized_range_valid(Address start, uint64_t size)
{
  // The fact stores start+size rather than an exclusive end, so a one-byte
  // access at UINT64_MAX is representable and valid.  Compare the final byte
  // offset to avoid overflowing start+size.
  return size != 0 && (size - 1) <= std::numeric_limits<Address>::max() - start;
}

class Writer
{
public:
  void raw(const uint8_t *data, size_t size)
  {
    if (size == 0)
      return;
    bytes_.insert(bytes_.end(), data, data + size);
  }

  void u8(uint8_t value) { bytes_.push_back(value); }

  void boolean(bool value) { u8(value ? 1 : 0); }

  void u16(uint16_t value)
  {
    u8(static_cast<uint8_t>(value >> 8));
    u8(static_cast<uint8_t>(value));
  }

  void u32(uint32_t value)
  {
    u8(static_cast<uint8_t>(value >> 24));
    u8(static_cast<uint8_t>(value >> 16));
    u8(static_cast<uint8_t>(value >> 8));
    u8(static_cast<uint8_t>(value));
  }

  void u64(uint64_t value)
  {
    for (int shift = 56; shift >= 0; shift -= 8)
      u8(static_cast<uint8_t>(value >> shift));
  }

  void i64(int64_t value) { u64(static_cast<uint64_t>(value)); }

  bool string(const std::string &value, std::string *error)
  {
    if (value.size() > std::numeric_limits<uint32_t>::max())
      return fail(error, "string exceeds the canonical 32-bit length limit");
    u32(static_cast<uint32_t>(value.size()));
    raw(reinterpret_cast<const uint8_t *>(value.data()), value.size());
    return true;
  }

  bool blob(const std::vector<uint8_t> &value, std::string *error)
  {
    if (value.size() > std::numeric_limits<uint32_t>::max())
      return fail(error, "byte vector exceeds the canonical 32-bit length limit");
    u32(static_cast<uint32_t>(value.size()));
    raw(value.data(), value.size());
    return true;
  }

  std::vector<uint8_t> take() { return std::move(bytes_); }

private:
  std::vector<uint8_t> bytes_;
};

class Reader
{
public:
  Reader(const std::vector<uint8_t> &bytes, const FactCodecLimits &limits)
    : bytes_(bytes), limits_(limits)
  {
  }

  bool raw(uint8_t *out, size_t size)
  {
    if (size > remaining())
      return set_error("truncated canonical input");
    if (size != 0)
      std::memcpy(out, bytes_.data() + pos_, size);
    pos_ += size;
    return true;
  }

  bool magic(const uint8_t expected[4])
  {
    uint8_t actual[4]{};
    if (!raw(actual, sizeof(actual)))
      return false;
    if (std::memcmp(actual, expected, sizeof(actual)) != 0)
      return set_error("canonical input has the wrong magic");
    return true;
  }

  bool u8(uint8_t &out)
  {
    if (remaining() < 1)
      return set_error("truncated canonical input");
    out = bytes_[pos_++];
    return true;
  }

  bool boolean(bool &out)
  {
    uint8_t value = 0;
    if (!u8(value))
      return false;
    if (value > 1)
      return set_error("invalid canonical boolean");
    out = value != 0;
    return true;
  }

  bool u16(uint16_t &out)
  {
    uint8_t a = 0, b = 0;
    if (!u8(a) || !u8(b))
      return false;
    out = static_cast<uint16_t>((static_cast<uint16_t>(a) << 8) | b);
    return true;
  }

  bool u32(uint32_t &out)
  {
    uint8_t bytes[4]{};
    if (!raw(bytes, sizeof(bytes)))
      return false;
    out = (static_cast<uint32_t>(bytes[0]) << 24) |
          (static_cast<uint32_t>(bytes[1]) << 16) |
          (static_cast<uint32_t>(bytes[2]) << 8) |
          static_cast<uint32_t>(bytes[3]);
    return true;
  }

  bool u64(uint64_t &out)
  {
    uint8_t bytes[8]{};
    if (!raw(bytes, sizeof(bytes)))
      return false;
    out = 0;
    for (uint8_t byte : bytes)
      out = (out << 8) | byte;
    return true;
  }

  bool i64(int64_t &out)
  {
    uint64_t raw_value = 0;
    if (!u64(raw_value))
      return false;
    if (raw_value <= static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
      out = static_cast<int64_t>(raw_value);
    else
      out = -static_cast<int64_t>(std::numeric_limits<uint64_t>::max() - raw_value) - 1;
    return true;
  }

  bool string(std::string &out)
  {
    uint32_t size = 0;
    if (!u32(size))
      return false;
    if (size > limits_.max_string_bytes)
      return set_error("canonical string exceeds configured decode limit");
    if (size > remaining())
      return set_error("truncated canonical string");
    out.assign(reinterpret_cast<const char *>(bytes_.data() + pos_), size);
    pos_ += size;
    return true;
  }

  bool blob(std::vector<uint8_t> &out)
  {
    uint32_t size = 0;
    if (!u32(size))
      return false;
    if (size > limits_.max_fact_bytes)
      return set_error("canonical byte vector exceeds configured decode limit");
    if (size > remaining())
      return set_error("truncated canonical byte vector");
    out.assign(bytes_.begin() + static_cast<std::ptrdiff_t>(pos_),
               bytes_.begin() + static_cast<std::ptrdiff_t>(pos_ + size));
    pos_ += size;
    return true;
  }

  bool count(uint32_t &out)
  {
    if (!u32(out))
      return false;
    if (out > limits_.max_vector_items)
      return set_error("canonical vector exceeds configured item limit");
    return true;
  }

  template <typename T, typename Fn>
  bool optional(std::optional<T> &out, Fn read_value)
  {
    uint8_t present = 0;
    if (!u8(present))
      return false;
    if (present > 1)
      return set_error("invalid canonical optional tag");
    if (present == 0)
    {
      out.reset();
      return true;
    }
    T value{};
    if (!read_value(value))
      return false;
    out = std::move(value);
    return true;
  }

  size_t remaining() const { return bytes_.size() - pos_; }
  const std::string &error() const { return error_; }

private:
  bool set_error(const char *message)
  {
    if (error_.empty())
      error_ = message;
    return false;
  }

  const std::vector<uint8_t> &bytes_;
  const FactCodecLimits &limits_;
  size_t pos_ = 0;
  std::string error_;
};

template <typename T>
void write_optional_u64(Writer &writer, const std::optional<T> &value)
{
  writer.u8(value.has_value() ? 1 : 0);
  if (value.has_value())
    writer.u64(static_cast<uint64_t>(*value));
}

void write_optional_i64(Writer &writer, const std::optional<int64_t> &value)
{
  writer.u8(value.has_value() ? 1 : 0);
  if (value.has_value())
    writer.i64(*value);
}

bool read_version(Reader &reader)
{
  uint16_t version = 0;
  return reader.u16(version) && version == kCodecVersion;
}

bool report_reader_error(const Reader &reader, std::string *error,
                         const char *fallback)
{
  return fail(error, reader.error().empty() ? fallback : reader.error());
}

bool validate_trait_value(const TraitValue &value, std::string *error)
{
  if (!enum_between(value.kind, TraitValueKind::None, TraitValueKind::Text))
    return fail(error, "function trait has an invalid value kind");
  if (value.kind != TraitValueKind::Text && !value.text_value.empty())
    return fail(error, "inactive function-trait text field is non-empty");
  if (value.kind != TraitValueKind::Signed && value.signed_value != 0)
    return fail(error, "inactive function-trait signed field is non-zero");
  if (value.kind != TraitValueKind::Unsigned && value.unsigned_value != 0)
    return fail(error, "inactive function-trait unsigned field is non-zero");
  if (value.kind != TraitValueKind::Boolean && value.boolean_value)
    return fail(error, "inactive function-trait boolean field is non-zero");
  return true;
}

bool validate_trait_value_for_kind(FunctionTraitKind trait,
                                   const TraitValue &value,
                                   std::string *error)
{
  const auto require = [&](bool condition, const char *expectation) {
    return condition || fail(error, std::string("function trait requires ") + expectation);
  };
  switch (trait)
  {
    case FunctionTraitKind::Returns:
    case FunctionTraitKind::NoReturn:
    case FunctionTraitKind::Leaf:
    case FunctionTraitKind::Thunk:
      return require(value.kind == TraitValueKind::None, "no value");
    case FunctionTraitKind::StackDelta:
      return require(value.kind == TraitValueKind::Signed, "a signed stack delta");
    case FunctionTraitKind::ArgumentRegister:
      return require(value.kind == TraitValueKind::Unsigned ||
                     value.kind == TraitValueKind::Text,
                     "an unsigned register id or register name");
    case FunctionTraitKind::ReturnConstant:
      return require(value.kind == TraitValueKind::Signed ||
                     value.kind == TraitValueKind::Unsigned,
                     "a signed or unsigned return constant");
    case FunctionTraitKind::WrapperTarget:
      return require(value.kind == TraitValueKind::Unsigned,
                     "an unsigned wrapper target address");
    case FunctionTraitKind::CallingConvention:
      return require(value.kind == TraitValueKind::Text,
                     "a calling-convention name");
    case FunctionTraitKind::Other:
      return true;
  }
  return false;
}

uint64_t string_code_unit_size(StringEncoding encoding)
{
  switch (encoding)
  {
    case StringEncoding::Utf16LE:
    case StringEncoding::Utf16BE:
      return 2;
    case StringEncoding::Utf32LE:
    case StringEncoding::Utf32BE:
      return 4;
    default:
      return 1;
  }
}

bool valid_utf8(const std::vector<uint8_t> &bytes)
{
  size_t i = 0;
  while (i < bytes.size())
  {
    const uint8_t first = bytes[i++];
    if (first <= 0x7f)
      continue;
    uint32_t codepoint = 0;
    size_t continuation_count = 0;
    uint32_t minimum = 0;
    if (first >= 0xc2 && first <= 0xdf)
    {
      codepoint = first & 0x1fu;
      continuation_count = 1;
      minimum = 0x80;
    }
    else if (first >= 0xe0 && first <= 0xef)
    {
      codepoint = first & 0x0fu;
      continuation_count = 2;
      minimum = 0x800;
    }
    else if (first >= 0xf0 && first <= 0xf4)
    {
      codepoint = first & 0x07u;
      continuation_count = 3;
      minimum = 0x10000;
    }
    else
    {
      return false;
    }
    if (continuation_count > bytes.size() - i)
      return false;
    for (size_t n = 0; n != continuation_count; ++n)
    {
      const uint8_t continuation = bytes[i++];
      if ((continuation & 0xc0u) != 0x80u)
        return false;
      codepoint = (codepoint << 6) | (continuation & 0x3fu);
    }
    if (codepoint < minimum || codepoint > 0x10ffffu ||
        (codepoint >= 0xd800u && codepoint <= 0xdfffu))
      return false;
  }
  return true;
}

bool valid_utf8(const std::string &text)
{
  return valid_utf8(std::vector<uint8_t>(text.begin(), text.end()));
}

uint16_t read_u16_code_unit(const std::vector<uint8_t> &bytes,
                            size_t offset,
                            bool little_endian)
{
  if (little_endian)
    return static_cast<uint16_t>(bytes[offset] |
      (static_cast<uint16_t>(bytes[offset + 1]) << 8));
  return static_cast<uint16_t>((static_cast<uint16_t>(bytes[offset]) << 8) |
                               bytes[offset + 1]);
}

bool valid_utf16(const std::vector<uint8_t> &bytes, bool little_endian)
{
  if ((bytes.size() % 2) != 0)
    return false;
  for (size_t offset = 0; offset < bytes.size(); offset += 2)
  {
    const uint16_t unit = read_u16_code_unit(bytes, offset, little_endian);
    if (unit >= 0xd800u && unit <= 0xdbffu)
    {
      if (offset + 4 > bytes.size())
        return false;
      const uint16_t low = read_u16_code_unit(bytes, offset + 2, little_endian);
      if (low < 0xdc00u || low > 0xdfffu)
        return false;
      offset += 2;
    }
    else if (unit >= 0xdc00u && unit <= 0xdfffu)
    {
      return false;
    }
  }
  return true;
}

uint32_t read_u32_code_unit(const std::vector<uint8_t> &bytes,
                            size_t offset,
                            bool little_endian)
{
  if (little_endian)
  {
    return static_cast<uint32_t>(bytes[offset]) |
           (static_cast<uint32_t>(bytes[offset + 1]) << 8) |
           (static_cast<uint32_t>(bytes[offset + 2]) << 16) |
           (static_cast<uint32_t>(bytes[offset + 3]) << 24);
  }
  return (static_cast<uint32_t>(bytes[offset]) << 24) |
         (static_cast<uint32_t>(bytes[offset + 1]) << 16) |
         (static_cast<uint32_t>(bytes[offset + 2]) << 8) |
         static_cast<uint32_t>(bytes[offset + 3]);
}

bool valid_utf32(const std::vector<uint8_t> &bytes, bool little_endian)
{
  if ((bytes.size() % 4) != 0)
    return false;
  for (size_t offset = 0; offset < bytes.size(); offset += 4)
  {
    const uint32_t codepoint = read_u32_code_unit(bytes, offset, little_endian);
    if (codepoint > 0x10ffffu || (codepoint >= 0xd800u && codepoint <= 0xdfffu))
      return false;
  }
  return true;
}

bool string_bytes_match_encoding(const StringCandidateFact &fact)
{
  switch (fact.encoding)
  {
    case StringEncoding::Bytes:
      return true;
    case StringEncoding::Ascii:
      return std::all_of(fact.bytes.begin(), fact.bytes.end(),
                         [](uint8_t byte) { return byte <= 0x7f; });
    case StringEncoding::Utf8:
      return valid_utf8(fact.bytes);
    case StringEncoding::Utf16LE:
      return valid_utf16(fact.bytes, true);
    case StringEncoding::Utf16BE:
      return valid_utf16(fact.bytes, false);
    case StringEncoding::Utf32LE:
      return valid_utf32(fact.bytes, true);
    case StringEncoding::Utf32BE:
      return valid_utf32(fact.bytes, false);
  }
  return false;
}

bool proof_can_establish_unreachable(ProofKind proof)
{
  return proof == ProofKind::StaticProof || proof == ProofKind::SymbolicProof ||
         proof == ProofKind::Imported || proof == ProofKind::UserAsserted;
}

bool dispatch_case_less(const DispatchCase &lhs, const DispatchCase &rhs)
{
  if (lhs.selector.has_value() != rhs.selector.has_value())
    return lhs.selector.has_value(); // known selectors precede unknown selectors
  if (lhs.selector != rhs.selector)
    return lhs.selector < rhs.selector;
  return lhs.target < rhs.target;
}

bool dispatch_case_equal(const DispatchCase &lhs, const DispatchCase &rhs)
{
  return lhs.selector == rhs.selector && lhs.target == rhs.target;
}

bool call_value_less(const CallValue &lhs, const CallValue &rhs)
{
  return std::tie(lhs.ordinal, lhs.location, lhs.bytes) <
         std::tie(rhs.ordinal, rhs.location, rhs.bytes);
}

bool call_value_equal(const CallValue &lhs, const CallValue &rhs)
{
  return lhs.ordinal == rhs.ordinal && lhs.location == rhs.location &&
         lhs.bytes == rhs.bytes;
}

void normalize_call_values(std::vector<CallValue> &values)
{
  std::sort(values.begin(), values.end(), call_value_less);
  values.erase(std::unique(values.begin(), values.end(), call_value_equal), values.end());
}

bool validate_call_values(const std::vector<CallValue> &values,
                          const char *role,
                          std::string *error)
{
  if (values.size() > std::numeric_limits<uint32_t>::max())
    return fail(error, std::string("call ") + role +
                         " vector exceeds the canonical item limit");
  if (!std::is_sorted(values.begin(), values.end(), call_value_less))
    return fail(error, std::string("call ") + role +
                         " values are not canonically sorted");
  for (size_t i = 0; i != values.size(); ++i)
  {
    const CallValue &value = values[i];
    if (value.location.empty())
      return fail(error, std::string("call ") + role + " location is empty");
    if (value.bytes.empty())
      return fail(error, std::string("call ") + role + " value is empty");
    if (value.location.size() > std::numeric_limits<uint32_t>::max() ||
        value.bytes.size() > std::numeric_limits<uint32_t>::max())
      return fail(error, std::string("call ") + role +
                           " value exceeds a canonical length limit");
    if (i != 0 && values[i - 1].ordinal == value.ordinal &&
        values[i - 1].location == value.location)
      return fail(error, std::string("call ") + role +
                           " assigns one ABI location multiple values");
  }
  return true;
}

void normalize_trait_value(TraitValue &value)
{
  if (value.kind != TraitValueKind::Signed)
    value.signed_value = 0;
  if (value.kind != TraitValueKind::Unsigned)
    value.unsigned_value = 0;
  if (value.kind != TraitValueKind::Boolean)
    value.boolean_value = false;
  if (value.kind != TraitValueKind::Text)
    value.text_value.clear();
}

// Minimal SHA-256 used solely for stable evidence identities and persistence
// integrity.  It has no external dependencies and operates on canonical bytes.
class Sha256
{
public:
  void update(const uint8_t *data, size_t size)
  {
    total_bytes_ += size;
    while (size != 0)
    {
      const size_t take = std::min(size, block_.size() - block_size_);
      std::memcpy(block_.data() + block_size_, data, take);
      block_size_ += take;
      data += take;
      size -= take;
      if (block_size_ == block_.size())
      {
        transform(block_.data());
        block_size_ = 0;
      }
    }
  }

  FactDigest finish()
  {
    const uint64_t total_bits = total_bytes_ * 8;
    block_[block_size_++] = 0x80;
    if (block_size_ > 56)
    {
      std::fill(block_.begin() + static_cast<std::ptrdiff_t>(block_size_), block_.end(), 0);
      transform(block_.data());
      block_size_ = 0;
    }
    std::fill(block_.begin() + static_cast<std::ptrdiff_t>(block_size_),
              block_.begin() + 56, 0);
    for (unsigned i = 0; i != 8; ++i)
      block_[63 - i] = static_cast<uint8_t>(total_bits >> (i * 8));
    transform(block_.data());

    FactDigest digest;
    for (size_t i = 0; i != state_.size(); ++i)
    {
      digest.bytes[i * 4] = static_cast<uint8_t>(state_[i] >> 24);
      digest.bytes[i * 4 + 1] = static_cast<uint8_t>(state_[i] >> 16);
      digest.bytes[i * 4 + 2] = static_cast<uint8_t>(state_[i] >> 8);
      digest.bytes[i * 4 + 3] = static_cast<uint8_t>(state_[i]);
    }
    return digest;
  }

private:
  static uint32_t rotr(uint32_t value, unsigned count)
  {
    return (value >> count) | (value << (32 - count));
  }

  void transform(const uint8_t *block)
  {
    static constexpr uint32_t k[64] = {
      0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
      0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
      0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
      0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
      0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
      0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
      0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
      0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
      0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
      0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
      0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
      0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
      0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
      0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
      0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
      0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
    };

    uint32_t w[64]{};
    for (size_t i = 0; i != 16; ++i)
    {
      const size_t off = i * 4;
      w[i] = (static_cast<uint32_t>(block[off]) << 24) |
             (static_cast<uint32_t>(block[off + 1]) << 16) |
             (static_cast<uint32_t>(block[off + 2]) << 8) |
             static_cast<uint32_t>(block[off + 3]);
    }
    for (size_t i = 16; i != 64; ++i)
    {
      const uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
      const uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
    uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];
    for (size_t i = 0; i != 64; ++i)
    {
      const uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const uint32_t ch = (e & f) ^ (~e & g);
      const uint32_t temp1 = h + s1 + ch + k[i] + w[i];
      const uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
      const uint32_t temp2 = s0 + maj;
      h = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
    }
    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
  }

  std::array<uint32_t, 8> state_{{0x6a09e667u, 0xbb67ae85u,
                                  0x3c6ef372u, 0xa54ff53au,
                                  0x510e527fu, 0x9b05688cu,
                                  0x1f83d9abu, 0x5be0cd19u}};
  std::array<uint8_t, 64> block_{};
  size_t block_size_ = 0;
  uint64_t total_bytes_ = 0;
};

FactDigest digest_bytes(const std::vector<uint8_t> &bytes)
{
  Sha256 sha;
  sha.update(bytes.data(), bytes.size());
  return sha.finish();
}

bool encode_normalized_payload(const FactPayload &payload,
                               std::vector<uint8_t> &out,
                               std::string *error)
{
  Writer writer;
  writer.raw(kPayloadMagic, sizeof(kPayloadMagic));
  writer.u16(kCodecVersion);
  writer.u8(static_cast<uint8_t>(fact_kind(payload)));

  const bool encoded = std::visit([&](const auto &fact) -> bool {
    using T = typename std::decay<decltype(fact)>::type;
    if constexpr (std::is_same<T, CodeTargetFact>::value)
    {
      writer.u64(fact.from);
      writer.u64(fact.target);
      writer.u8(static_cast<uint8_t>(fact.kind));
      writer.boolean(fact.unique);
    }
    else if constexpr (std::is_same<T, BranchReachabilityFact>::value)
    {
      writer.u64(fact.branch);
      writer.u64(fact.successor);
      writer.u8(static_cast<uint8_t>(fact.state));
    }
    else if constexpr (std::is_same<T, MemoryAccessFact>::value)
    {
      writer.u64(fact.instruction);
      writer.u64(fact.address);
      writer.u32(fact.size);
      writer.u8(static_cast<uint8_t>(fact.kind));
    }
    else if constexpr (std::is_same<T, MemoryValueFact>::value)
    {
      writer.u64(fact.instruction);
      writer.u64(fact.address);
      writer.u8(static_cast<uint8_t>(fact.kind));
      if (!writer.blob(fact.bytes, error))
        return false;
    }
    else if constexpr (std::is_same<T, StringCandidateFact>::value)
    {
      writer.u64(fact.address);
      writer.u8(static_cast<uint8_t>(fact.encoding));
      if (!writer.blob(fact.bytes, error) || !writer.string(fact.decoded, error))
        return false;
      writer.boolean(fact.null_terminated);
    }
    else if constexpr (std::is_same<T, FunctionCandidateFact>::value)
    {
      writer.u64(fact.entry);
      write_optional_u64(writer, fact.end);
      writer.u8(static_cast<uint8_t>(fact.kind));
    }
    else if constexpr (std::is_same<T, FunctionTraitFact>::value)
    {
      writer.u64(fact.function);
      writer.u8(static_cast<uint8_t>(fact.trait));
      writer.u8(static_cast<uint8_t>(fact.value.kind));
      writer.i64(fact.value.signed_value);
      writer.u64(fact.value.unsigned_value);
      writer.boolean(fact.value.boolean_value);
      if (!writer.string(fact.value.text_value, error))
        return false;
    }
    else if constexpr (std::is_same<T, CodeRegionFact>::value)
    {
      writer.u64(fact.start);
      writer.u64(fact.end);
      writer.u8(static_cast<uint8_t>(fact.kind));
    }
    else if constexpr (std::is_same<T, DispatchMapFact>::value)
    {
      writer.u64(fact.site);
      writer.u32(static_cast<uint32_t>(fact.cases.size()));
      for (const DispatchCase &dispatch_case : fact.cases)
      {
        write_optional_u64(writer, dispatch_case.selector);
        writer.u64(dispatch_case.target);
      }
      write_optional_u64(writer, fact.default_target);
      writer.boolean(fact.complete);
    }
    else if constexpr (std::is_same<T, CfgCandidateFact>::value)
    {
      writer.u64(fact.from);
      writer.u64(fact.to);
      writer.u8(static_cast<uint8_t>(fact.kind));
      writer.u8(static_cast<uint8_t>(fact.state));
    }
    else if constexpr (std::is_same<T, FunctionOutcomeFact>::value)
    {
      writer.u64(fact.function);
      writer.u8(static_cast<uint8_t>(fact.stop));
      write_optional_u64(writer, fact.stop_pc);
      write_optional_i64(writer, fact.stack_delta);
      write_optional_u64(writer, fact.instruction_count);
    }
    else if constexpr (std::is_same<T, RegisterValueFact>::value)
    {
      writer.u64(fact.instruction);
      writer.u8(static_cast<uint8_t>(fact.point));
      if (!writer.string(fact.register_id, error) || !writer.blob(fact.bytes, error))
        return false;
    }
    else if constexpr (std::is_same<T, CallObservationFact>::value)
    {
      writer.u64(fact.source);
      write_optional_u64(writer, fact.target);
      writer.u8(static_cast<uint8_t>(fact.kind));
      writer.u8(static_cast<uint8_t>(fact.result));
      writer.u32(static_cast<uint32_t>(fact.arguments.size()));
      for (const CallValue &value : fact.arguments)
      {
        writer.u32(value.ordinal);
        if (!writer.string(value.location, error) || !writer.blob(value.bytes, error))
          return false;
      }
      writer.u32(static_cast<uint32_t>(fact.returns.size()));
      for (const CallValue &value : fact.returns)
      {
        writer.u32(value.ordinal);
        if (!writer.string(value.location, error) || !writer.blob(value.bytes, error))
          return false;
      }
    }
    else
    {
      static_assert(always_false<T>::value, "FactPayload alternative lacks an encoder");
    }
    return true;
  }, payload);

  if (!encoded)
    return false;
  out = writer.take();
  return true;
}

bool encode_normalized_evidence(const Evidence &evidence,
                                std::vector<uint8_t> &out,
                                std::string *error)
{
  Writer writer;
  writer.raw(kEvidenceMagic, sizeof(kEvidenceMagic));
  writer.u16(kCodecVersion);
  if (!writer.string(evidence.producer, error) || !writer.string(evidence.method, error))
    return false;
  writer.u8(static_cast<uint8_t>(evidence.proof));
  writer.u16(evidence.confidence);
  write_optional_u64(writer, evidence.scope.run_id);
  write_optional_u64(writer, evidence.scope.seed);
  write_optional_u64(writer, evidence.scope.function_start);
  write_optional_u64(writer, evidence.scope.function_end);
  writer.u64(evidence.scope.generation);
  if (evidence.support_addresses.size() > std::numeric_limits<uint32_t>::max())
    return fail(error, "support-address vector exceeds the canonical 32-bit item limit");
  writer.u32(static_cast<uint32_t>(evidence.support_addresses.size()));
  for (Address address : evidence.support_addresses)
    writer.u64(address);
  if (!writer.string(evidence.detail, error))
    return false;
  out = writer.take();
  return true;
}

template <typename T>
bool read_enum_u8(Reader &reader, T first, T last, T &out)
{
  uint8_t value = 0;
  if (!reader.u8(value))
    return false;
  out = static_cast<T>(value);
  return enum_between(out, first, last);
}

bool read_optional_u64(Reader &reader, std::optional<uint64_t> &out)
{
  return reader.optional<uint64_t>(out, [&](uint64_t &value) { return reader.u64(value); });
}

bool read_optional_i64(Reader &reader, std::optional<int64_t> &out)
{
  return reader.optional<int64_t>(out, [&](int64_t &value) { return reader.i64(value); });
}

bool decode_payload_body(Reader &reader, FactKind kind, FactPayload &out)
{
  switch (kind)
  {
    case FactKind::CodeTarget:
    {
      CodeTargetFact fact;
      if (!reader.u64(fact.from) || !reader.u64(fact.target) ||
          !read_enum_u8(reader, CodeTargetKind::Unknown, CodeTargetKind::Exception, fact.kind) ||
          !reader.boolean(fact.unique))
        return false;
      out = fact;
      return true;
    }
    case FactKind::BranchReachability:
    {
      BranchReachabilityFact fact;
      if (!reader.u64(fact.branch) || !reader.u64(fact.successor) ||
          !read_enum_u8(reader, Reachability::NotObserved,
                        Reachability::ProvenUnreachable, fact.state))
        return false;
      out = fact;
      return true;
    }
    case FactKind::MemoryAccess:
    {
      MemoryAccessFact fact;
      if (!reader.u64(fact.instruction) || !reader.u64(fact.address) ||
          !reader.u32(fact.size) ||
          !read_enum_u8(reader, MemoryAccessKind::Read, MemoryAccessKind::ReadWrite, fact.kind))
        return false;
      out = fact;
      return true;
    }
    case FactKind::MemoryValue:
    {
      MemoryValueFact fact;
      if (!reader.u64(fact.instruction) || !reader.u64(fact.address) ||
          !read_enum_u8(reader, MemoryAccessKind::Read, MemoryAccessKind::ReadWrite, fact.kind) ||
          !reader.blob(fact.bytes))
        return false;
      out = std::move(fact);
      return true;
    }
    case FactKind::StringCandidate:
    {
      StringCandidateFact fact;
      if (!reader.u64(fact.address) ||
          !read_enum_u8(reader, StringEncoding::Bytes, StringEncoding::Utf32BE, fact.encoding) ||
          !reader.blob(fact.bytes) || !reader.string(fact.decoded) ||
          !reader.boolean(fact.null_terminated))
        return false;
      out = std::move(fact);
      return true;
    }
    case FactKind::FunctionCandidate:
    {
      FunctionCandidateFact fact;
      if (!reader.u64(fact.entry) || !read_optional_u64(reader, fact.end) ||
          !read_enum_u8(reader, FunctionCandidateKind::Other,
                        FunctionCandidateKind::UserAsserted, fact.kind))
        return false;
      out = fact;
      return true;
    }
    case FactKind::FunctionTrait:
    {
      FunctionTraitFact fact;
      if (!reader.u64(fact.function) ||
          !read_enum_u8(reader, FunctionTraitKind::Other,
                        FunctionTraitKind::CallingConvention, fact.trait) ||
          !read_enum_u8(reader, TraitValueKind::None, TraitValueKind::Text, fact.value.kind) ||
          !reader.i64(fact.value.signed_value) || !reader.u64(fact.value.unsigned_value) ||
          !reader.boolean(fact.value.boolean_value) || !reader.string(fact.value.text_value))
        return false;
      out = std::move(fact);
      return true;
    }
    case FactKind::CodeRegion:
    {
      CodeRegionFact fact;
      if (!reader.u64(fact.start) || !reader.u64(fact.end) ||
          !read_enum_u8(reader, CodeRegionKind::Unknown, CodeRegionKind::Padding, fact.kind))
        return false;
      out = fact;
      return true;
    }
    case FactKind::DispatchMap:
    {
      DispatchMapFact fact;
      uint32_t count = 0;
      if (!reader.u64(fact.site) || !reader.count(count))
        return false;
      fact.cases.reserve(count);
      for (uint32_t i = 0; i != count; ++i)
      {
        DispatchCase dispatch_case;
        if (!read_optional_u64(reader, dispatch_case.selector) ||
            !reader.u64(dispatch_case.target))
          return false;
        fact.cases.push_back(dispatch_case);
      }
      if (!read_optional_u64(reader, fact.default_target) || !reader.boolean(fact.complete))
        return false;
      out = std::move(fact);
      return true;
    }
    case FactKind::CfgCandidate:
    {
      CfgCandidateFact fact;
      if (!reader.u64(fact.from) || !reader.u64(fact.to) ||
          !read_enum_u8(reader, CfgEdgeKind::Unknown, CfgEdgeKind::Indirect, fact.kind) ||
          !read_enum_u8(reader, Reachability::NotObserved,
                        Reachability::ProvenUnreachable, fact.state))
        return false;
      out = fact;
      return true;
    }
    case FactKind::FunctionOutcome:
    {
      FunctionOutcomeFact fact;
      if (!reader.u64(fact.function) ||
          !read_enum_u8(reader, FunctionStopKind::Unknown,
                        FunctionStopKind::TerminatedProcess, fact.stop) ||
          !read_optional_u64(reader, fact.stop_pc) ||
          !read_optional_i64(reader, fact.stack_delta) ||
          !read_optional_u64(reader, fact.instruction_count))
        return false;
      out = fact;
      return true;
    }
    case FactKind::RegisterValue:
    {
      RegisterValueFact fact;
      if (!reader.u64(fact.instruction) ||
          !read_enum_u8(reader, RegisterStatePoint::BeforeInstruction,
                        RegisterStatePoint::CallReturn, fact.point) ||
          !reader.string(fact.register_id) || !reader.blob(fact.bytes))
        return false;
      out = std::move(fact);
      return true;
    }
    case FactKind::CallObservation:
    {
      CallObservationFact fact;
      if (!reader.u64(fact.source) || !read_optional_u64(reader, fact.target) ||
          !read_enum_u8(reader, CallKind::Unknown, CallKind::ImportedCall, fact.kind) ||
          !read_enum_u8(reader, CallResult::Unknown, CallResult::TimedOut, fact.result))
        return false;
      uint32_t argument_count = 0;
      if (!reader.count(argument_count))
        return false;
      fact.arguments.reserve(argument_count);
      for (uint32_t i = 0; i != argument_count; ++i)
      {
        CallValue value;
        if (!reader.u32(value.ordinal) || !reader.string(value.location) ||
            !reader.blob(value.bytes))
          return false;
        fact.arguments.push_back(std::move(value));
      }
      uint32_t return_count = 0;
      if (!reader.count(return_count))
        return false;
      fact.returns.reserve(return_count);
      for (uint32_t i = 0; i != return_count; ++i)
      {
        CallValue value;
        if (!reader.u32(value.ordinal) || !reader.string(value.location) ||
            !reader.blob(value.bytes))
          return false;
        fact.returns.push_back(std::move(value));
      }
      out = std::move(fact);
      return true;
    }
  }
  return false;
}

std::vector<uint8_t> invalid_sort_key(const std::string &message)
{
  std::vector<uint8_t> key;
  key.reserve(message.size() + 1);
  key.push_back(0xff);
  key.insert(key.end(), message.begin(), message.end());
  return key;
}

} // namespace

TraitValue TraitValue::none()
{
  return {};
}

TraitValue TraitValue::signed_integer(int64_t value)
{
  TraitValue result;
  result.kind = TraitValueKind::Signed;
  result.signed_value = value;
  return result;
}

TraitValue TraitValue::unsigned_integer(uint64_t value)
{
  TraitValue result;
  result.kind = TraitValueKind::Unsigned;
  result.unsigned_value = value;
  return result;
}

TraitValue TraitValue::boolean(bool value)
{
  TraitValue result;
  result.kind = TraitValueKind::Boolean;
  result.boolean_value = value;
  return result;
}

TraitValue TraitValue::text(std::string value)
{
  TraitValue result;
  result.kind = TraitValueKind::Text;
  result.text_value = std::move(value);
  return result;
}

std::string FactDigest::hex() const
{
  std::ostringstream stream;
  stream << std::hex << std::setfill('0');
  for (uint8_t byte : bytes)
    stream << std::setw(2) << static_cast<unsigned>(byte);
  return stream.str();
}

bool operator==(const FactDigest &lhs, const FactDigest &rhs)
{
  return lhs.bytes == rhs.bytes;
}

bool operator!=(const FactDigest &lhs, const FactDigest &rhs)
{
  return !(lhs == rhs);
}

bool operator<(const FactDigest &lhs, const FactDigest &rhs)
{
  return lhs.bytes < rhs.bytes;
}

FactKind fact_kind(const FactPayload &payload)
{
  return std::visit([](const auto &fact) -> FactKind {
    using T = typename std::decay<decltype(fact)>::type;
    if constexpr (std::is_same<T, CodeTargetFact>::value)
      return FactKind::CodeTarget;
    else if constexpr (std::is_same<T, BranchReachabilityFact>::value)
      return FactKind::BranchReachability;
    else if constexpr (std::is_same<T, MemoryAccessFact>::value)
      return FactKind::MemoryAccess;
    else if constexpr (std::is_same<T, MemoryValueFact>::value)
      return FactKind::MemoryValue;
    else if constexpr (std::is_same<T, StringCandidateFact>::value)
      return FactKind::StringCandidate;
    else if constexpr (std::is_same<T, FunctionCandidateFact>::value)
      return FactKind::FunctionCandidate;
    else if constexpr (std::is_same<T, FunctionTraitFact>::value)
      return FactKind::FunctionTrait;
    else if constexpr (std::is_same<T, CodeRegionFact>::value)
      return FactKind::CodeRegion;
    else if constexpr (std::is_same<T, DispatchMapFact>::value)
      return FactKind::DispatchMap;
    else if constexpr (std::is_same<T, CfgCandidateFact>::value)
      return FactKind::CfgCandidate;
    else if constexpr (std::is_same<T, FunctionOutcomeFact>::value)
      return FactKind::FunctionOutcome;
    else if constexpr (std::is_same<T, RegisterValueFact>::value)
      return FactKind::RegisterValue;
    else if constexpr (std::is_same<T, CallObservationFact>::value)
      return FactKind::CallObservation;
    else
    {
      static_assert(always_false<T>::value, "FactPayload alternative lacks a FactKind");
      return FactKind::CodeTarget;
    }
  }, payload);
}

const char *fact_kind_name(FactKind kind)
{
  switch (kind)
  {
    case FactKind::CodeTarget: return "CodeTarget";
    case FactKind::BranchReachability: return "BranchReachability";
    case FactKind::MemoryAccess: return "MemoryAccess";
    case FactKind::MemoryValue: return "MemoryValue";
    case FactKind::StringCandidate: return "StringCandidate";
    case FactKind::FunctionCandidate: return "FunctionCandidate";
    case FactKind::FunctionTrait: return "FunctionTrait";
    case FactKind::CodeRegion: return "CodeRegion";
    case FactKind::DispatchMap: return "DispatchMap";
    case FactKind::CfgCandidate: return "CfgCandidate";
    case FactKind::FunctionOutcome: return "FunctionOutcome";
    case FactKind::RegisterValue: return "RegisterValue";
    case FactKind::CallObservation: return "CallObservation";
  }
  return "Invalid";
}

bool normalize_payload(FactPayload &payload, std::string *error)
{
  std::visit([](auto &fact) {
    using T = typename std::decay<decltype(fact)>::type;
    if constexpr (std::is_same<T, FunctionTraitFact>::value)
    {
      normalize_trait_value(fact.value);
    }
    else if constexpr (std::is_same<T, DispatchMapFact>::value)
    {
      std::sort(fact.cases.begin(), fact.cases.end(), dispatch_case_less);
      fact.cases.erase(std::unique(fact.cases.begin(), fact.cases.end(), dispatch_case_equal),
                       fact.cases.end());
    }
    else if constexpr (std::is_same<T, CallObservationFact>::value)
    {
      normalize_call_values(fact.arguments);
      normalize_call_values(fact.returns);
    }
  }, payload);
  return validate_payload(payload, error);
}

bool normalize_evidence(Evidence &evidence, std::string *error)
{
  std::sort(evidence.support_addresses.begin(), evidence.support_addresses.end());
  evidence.support_addresses.erase(
    std::unique(evidence.support_addresses.begin(), evidence.support_addresses.end()),
    evidence.support_addresses.end());
  return validate_evidence(evidence, error);
}

bool normalize_fact(AnalysisFact &fact, std::string *error)
{
  if (!normalize_payload(fact.payload, error))
    return false;
  if (!normalize_evidence(fact.evidence, error))
    return false;
  return validate_fact(fact, error);
}

bool validate_payload(const FactPayload &payload, std::string *error)
{
  return std::visit([&](const auto &fact) -> bool {
    using T = typename std::decay<decltype(fact)>::type;
    if constexpr (std::is_same<T, CodeTargetFact>::value)
    {
      if (!enum_between(fact.kind, CodeTargetKind::Unknown, CodeTargetKind::Exception))
        return fail(error, "code-target fact has an invalid target kind");
    }
    else if constexpr (std::is_same<T, BranchReachabilityFact>::value)
    {
      if (!enum_between(fact.state, Reachability::NotObserved,
                        Reachability::ProvenUnreachable))
        return fail(error, "branch-reachability fact has an invalid state");
    }
    else if constexpr (std::is_same<T, MemoryAccessFact>::value)
    {
      if (!enum_between(fact.kind, MemoryAccessKind::Read, MemoryAccessKind::ReadWrite))
        return fail(error, "memory-access fact has an invalid access kind");
      if (!sized_range_valid(fact.address, fact.size))
        return fail(error, "memory-access fact has an empty or overflowing address range");
    }
    else if constexpr (std::is_same<T, MemoryValueFact>::value)
    {
      if (!enum_between(fact.kind, MemoryAccessKind::Read, MemoryAccessKind::ReadWrite))
        return fail(error, "memory-value fact has an invalid access kind");
      if (!sized_range_valid(fact.address, fact.bytes.size()))
        return fail(error, "memory-value fact has an empty or overflowing byte range");
      if (fact.bytes.size() > std::numeric_limits<uint32_t>::max())
        return fail(error, "memory-value fact exceeds the canonical byte limit");
    }
    else if constexpr (std::is_same<T, StringCandidateFact>::value)
    {
      if (!enum_between(fact.encoding, StringEncoding::Bytes, StringEncoding::Utf32BE))
        return fail(error, "string-candidate fact has an invalid encoding");
      if (fact.bytes.empty() && !fact.null_terminated)
        return fail(error, "empty string candidate must include a terminator observation");
      if (fact.bytes.size() > std::numeric_limits<uint32_t>::max() ||
          fact.decoded.size() > std::numeric_limits<uint32_t>::max())
        return fail(error, "string-candidate fact exceeds a canonical length limit");
      if (!string_bytes_match_encoding(fact))
        return fail(error, "string-candidate bytes are invalid for the declared encoding");
      if (!fact.decoded.empty() && !valid_utf8(fact.decoded))
        return fail(error, "string-candidate display text is not valid UTF-8");
      const uint64_t terminator_size = fact.null_terminated
        ? string_code_unit_size(fact.encoding) : 0;
      const uint64_t content_size = static_cast<uint64_t>(fact.bytes.size());
      if (content_size > std::numeric_limits<uint64_t>::max() - terminator_size ||
          !sized_range_valid(fact.address, content_size + terminator_size))
        return fail(error, "string-candidate fact has an overflowing address range");
    }
    else if constexpr (std::is_same<T, FunctionCandidateFact>::value)
    {
      if (!enum_between(fact.kind, FunctionCandidateKind::Other,
                        FunctionCandidateKind::UserAsserted))
        return fail(error, "function-candidate fact has an invalid candidate kind");
      if (fact.end.has_value() && !range_valid(fact.entry, *fact.end))
        return fail(error, "function-candidate fact has an invalid range");
    }
    else if constexpr (std::is_same<T, FunctionTraitFact>::value)
    {
      if (!enum_between(fact.trait, FunctionTraitKind::Other,
                        FunctionTraitKind::CallingConvention))
        return fail(error, "function-trait fact has an invalid trait kind");
      if (!validate_trait_value(fact.value, error))
        return false;
      if (!validate_trait_value_for_kind(fact.trait, fact.value, error))
        return false;
    }
    else if constexpr (std::is_same<T, CodeRegionFact>::value)
    {
      if (!enum_between(fact.kind, CodeRegionKind::Unknown, CodeRegionKind::Padding))
        return fail(error, "code-region fact has an invalid region kind");
      if (!range_valid(fact.start, fact.end))
        return fail(error, "code-region fact has an empty or inverted range");
    }
    else if constexpr (std::is_same<T, DispatchMapFact>::value)
    {
      if (fact.cases.empty() && !fact.default_target.has_value())
        return fail(error, "dispatch-map fact has no destinations");
      if (fact.cases.size() > std::numeric_limits<uint32_t>::max())
        return fail(error, "dispatch-map fact exceeds the canonical item limit");
      std::vector<DispatchCase> normalized = fact.cases;
      std::sort(normalized.begin(), normalized.end(), dispatch_case_less);
      if (!std::equal(normalized.begin(), normalized.end(), fact.cases.begin(),
                      dispatch_case_equal))
        return fail(error, "dispatch-map cases are not canonically sorted");
      if (std::adjacent_find(fact.cases.begin(), fact.cases.end(),
                             dispatch_case_equal) != fact.cases.end())
        return fail(error, "dispatch-map cases contain an exact duplicate");
      for (size_t i = 1; i < fact.cases.size(); ++i)
      {
        const DispatchCase &previous = fact.cases[i - 1];
        const DispatchCase &current = fact.cases[i];
        if (previous.selector.has_value() && current.selector == previous.selector &&
            current.target != previous.target)
          return fail(error, "one dispatch map assigns a selector to multiple targets");
      }
    }
    else if constexpr (std::is_same<T, CfgCandidateFact>::value)
    {
      if (!enum_between(fact.kind, CfgEdgeKind::Unknown, CfgEdgeKind::Indirect))
        return fail(error, "CFG-candidate fact has an invalid edge kind");
      if (!enum_between(fact.state, Reachability::NotObserved,
                        Reachability::ProvenUnreachable))
        return fail(error, "CFG-candidate fact has an invalid reachability state");
    }
    else if constexpr (std::is_same<T, FunctionOutcomeFact>::value)
    {
      if (!enum_between(fact.stop, FunctionStopKind::Unknown,
                        FunctionStopKind::TerminatedProcess))
        return fail(error, "function-outcome fact has an invalid stop kind");
    }
    else if constexpr (std::is_same<T, RegisterValueFact>::value)
    {
      if (!enum_between(fact.point, RegisterStatePoint::BeforeInstruction,
                        RegisterStatePoint::CallReturn))
        return fail(error, "register-value fact has an invalid state point");
      if (fact.register_id.empty())
        return fail(error, "register-value fact has an empty register id");
      if (fact.bytes.empty())
        return fail(error, "register-value fact has an empty value");
      if (fact.register_id.size() > std::numeric_limits<uint32_t>::max() ||
          fact.bytes.size() > std::numeric_limits<uint32_t>::max())
        return fail(error, "register-value fact exceeds a canonical length limit");
    }
    else if constexpr (std::is_same<T, CallObservationFact>::value)
    {
      if (!enum_between(fact.kind, CallKind::Unknown, CallKind::ImportedCall))
        return fail(error, "call-observation fact has an invalid call kind");
      if (!enum_between(fact.result, CallResult::Unknown, CallResult::TimedOut))
        return fail(error, "call-observation fact has an invalid result");
      if (!validate_call_values(fact.arguments, "argument", error) ||
          !validate_call_values(fact.returns, "return", error))
        return false;
      if (!fact.returns.empty() && fact.result != CallResult::Returned)
        return fail(error, "call return values require a Returned result");
    }
    else
    {
      static_assert(always_false<T>::value, "FactPayload alternative lacks validation");
    }
    return true;
  }, payload);
}

bool validate_evidence(const Evidence &evidence, std::string *error)
{
  if (evidence.producer.empty())
    return fail(error, "evidence producer id is empty");
  if (evidence.method.empty())
    return fail(error, "evidence method id is empty");
  if (!enum_between(evidence.proof, ProofKind::Unknown, ProofKind::UserAsserted))
    return fail(error, "evidence has an invalid proof kind");
  if (evidence.confidence > kMaxConfidence)
    return fail(error, "evidence confidence exceeds 10000 basis points");
  if (evidence.scope.function_end.has_value() &&
      !evidence.scope.function_start.has_value())
    return fail(error, "evidence function_end is present without function_start");
  if (evidence.scope.function_start.has_value() &&
      evidence.scope.function_end.has_value() &&
      !range_valid(*evidence.scope.function_start, *evidence.scope.function_end))
    return fail(error, "evidence has an invalid function scope");
  if (!std::is_sorted(evidence.support_addresses.begin(),
                      evidence.support_addresses.end()))
    return fail(error, "evidence support addresses are not sorted");
  if (std::adjacent_find(evidence.support_addresses.begin(),
                         evidence.support_addresses.end()) !=
      evidence.support_addresses.end())
    return fail(error, "evidence support addresses contain duplicates");
  if (evidence.support_addresses.size() > std::numeric_limits<uint32_t>::max() ||
      evidence.producer.size() > std::numeric_limits<uint32_t>::max() ||
      evidence.method.size() > std::numeric_limits<uint32_t>::max() ||
      evidence.detail.size() > std::numeric_limits<uint32_t>::max())
    return fail(error, "evidence exceeds a canonical length limit");
  return true;
}

bool validate_fact(const AnalysisFact &fact, std::string *error)
{
  if (!validate_payload(fact.payload, error) || !validate_evidence(fact.evidence, error))
    return false;
  Reachability state = Reachability::NotObserved;
  bool has_reachability = false;
  if (const auto *branch = std::get_if<BranchReachabilityFact>(&fact.payload))
  {
    state = branch->state;
    has_reachability = true;
  }
  else if (const auto *edge = std::get_if<CfgCandidateFact>(&fact.payload))
  {
    state = edge->state;
    has_reachability = true;
  }
  if (has_reachability && state == Reachability::ProvenUnreachable &&
      !proof_can_establish_unreachable(fact.evidence.proof))
    return fail(error, "proven-unreachable evidence requires a static, symbolic, imported, or user proof");
  return true;
}

bool encode_payload(const FactPayload &payload,
                    std::vector<uint8_t> &out,
                    std::string *error)
{
  FactPayload normalized = payload;
  if (!normalize_payload(normalized, error))
    return false;
  std::vector<uint8_t> encoded;
  if (!encode_normalized_payload(normalized, encoded, error))
    return false;
  out = std::move(encoded);
  return true;
}

bool decode_payload(const std::vector<uint8_t> &bytes,
                    FactPayload &out,
                    std::string *error,
                    const FactCodecLimits &limits)
{
  if (bytes.size() > limits.max_fact_bytes)
    return fail(error, "payload exceeds configured decode limit");
  Reader reader(bytes, limits);
  uint8_t raw_kind = 0;
  if (!reader.magic(kPayloadMagic) || !read_version(reader) || !reader.u8(raw_kind))
    return report_reader_error(reader, error, "unsupported payload codec version");
  const FactKind kind = static_cast<FactKind>(raw_kind);
  if (!enum_between(kind, FactKind::CodeTarget, FactKind::CallObservation))
    return fail(error, "payload has an invalid fact kind");
  FactPayload decoded;
  if (!decode_payload_body(reader, kind, decoded))
    return report_reader_error(reader, error, "payload contains an invalid enum or field");
  if (reader.remaining() != 0)
    return fail(error, "payload has trailing bytes");
  FactPayload normalized = decoded;
  if (!normalize_payload(normalized, error))
    return false;
  std::vector<uint8_t> canonical;
  if (!encode_normalized_payload(normalized, canonical, error))
    return false;
  if (canonical != bytes)
    return fail(error, "payload is valid but non-canonical");
  out = std::move(normalized);
  return true;
}

bool encode_evidence(const Evidence &evidence,
                     std::vector<uint8_t> &out,
                     std::string *error)
{
  Evidence normalized = evidence;
  if (!normalize_evidence(normalized, error))
    return false;
  std::vector<uint8_t> encoded;
  if (!encode_normalized_evidence(normalized, encoded, error))
    return false;
  out = std::move(encoded);
  return true;
}

bool decode_evidence(const std::vector<uint8_t> &bytes,
                     Evidence &out,
                     std::string *error,
                     const FactCodecLimits &limits)
{
  if (bytes.size() > limits.max_fact_bytes)
    return fail(error, "evidence exceeds configured decode limit");
  Reader reader(bytes, limits);
  Evidence decoded;
  uint8_t proof = 0;
  if (!reader.magic(kEvidenceMagic) || !read_version(reader) ||
      !reader.string(decoded.producer) || !reader.string(decoded.method) ||
      !reader.u8(proof) || !reader.u16(decoded.confidence) ||
      !read_optional_u64(reader, decoded.scope.run_id) ||
      !read_optional_u64(reader, decoded.scope.seed) ||
      !read_optional_u64(reader, decoded.scope.function_start) ||
      !read_optional_u64(reader, decoded.scope.function_end) ||
      !reader.u64(decoded.scope.generation))
    return report_reader_error(reader, error, "invalid evidence header");
  decoded.proof = static_cast<ProofKind>(proof);
  uint32_t support_count = 0;
  if (!reader.count(support_count))
    return report_reader_error(reader, error, "invalid evidence support count");
  decoded.support_addresses.reserve(support_count);
  for (uint32_t i = 0; i != support_count; ++i)
  {
    Address address = 0;
    if (!reader.u64(address))
      return report_reader_error(reader, error, "truncated evidence support addresses");
    decoded.support_addresses.push_back(address);
  }
  if (!reader.string(decoded.detail))
    return report_reader_error(reader, error, "invalid evidence detail");
  if (reader.remaining() != 0)
    return fail(error, "evidence has trailing bytes");
  if (!validate_evidence(decoded, error))
    return false;
  std::vector<uint8_t> canonical;
  if (!encode_normalized_evidence(decoded, canonical, error))
    return false;
  if (canonical != bytes)
    return fail(error, "evidence is valid but non-canonical");
  out = std::move(decoded);
  return true;
}

bool encode_analysis_fact(const AnalysisFact &fact,
                          std::vector<uint8_t> &out,
                          std::string *error)
{
  AnalysisFact normalized = fact;
  if (!normalize_fact(normalized, error))
    return false;
  std::vector<uint8_t> payload_bytes;
  std::vector<uint8_t> evidence_bytes;
  if (!encode_normalized_payload(normalized.payload, payload_bytes, error) ||
      !encode_normalized_evidence(normalized.evidence, evidence_bytes, error))
    return false;
  Writer writer;
  writer.raw(kFactMagic, sizeof(kFactMagic));
  writer.u16(kCodecVersion);
  if (!writer.blob(payload_bytes, error) || !writer.blob(evidence_bytes, error))
    return false;
  out = writer.take();
  return true;
}

bool decode_analysis_fact(const std::vector<uint8_t> &bytes,
                          AnalysisFact &out,
                          std::string *error,
                          const FactCodecLimits &limits)
{
  if (bytes.size() > limits.max_fact_bytes)
    return fail(error, "analysis fact exceeds configured decode limit");
  Reader reader(bytes, limits);
  if (!reader.magic(kFactMagic) || !read_version(reader))
    return report_reader_error(reader, error, "unsupported analysis-fact codec version");
  std::vector<uint8_t> payload_bytes;
  std::vector<uint8_t> evidence_bytes;
  if (!reader.blob(payload_bytes) || !reader.blob(evidence_bytes))
    return report_reader_error(reader, error, "invalid length-delimited analysis fact");
  if (reader.remaining() != 0)
    return fail(error, "analysis fact has trailing bytes");
  AnalysisFact decoded;
  if (!decode_payload(payload_bytes, decoded.payload, error, limits) ||
      !decode_evidence(evidence_bytes, decoded.evidence, error, limits))
    return false;
  std::vector<uint8_t> canonical;
  if (!encode_analysis_fact(decoded, canonical, error))
    return false;
  if (canonical != bytes)
    return fail(error, "analysis fact is valid but non-canonical");
  out = std::move(decoded);
  return true;
}

bool stable_digest(const FactPayload &payload, FactDigest &out, std::string *error)
{
  std::vector<uint8_t> encoded;
  if (!encode_payload(payload, encoded, error))
    return false;
  out = digest_bytes(encoded);
  return true;
}

bool stable_digest(const Evidence &evidence, FactDigest &out, std::string *error)
{
  std::vector<uint8_t> encoded;
  if (!encode_evidence(evidence, encoded, error))
    return false;
  out = digest_bytes(encoded);
  return true;
}

bool stable_digest(const AnalysisFact &fact, FactDigest &out, std::string *error)
{
  std::vector<uint8_t> encoded;
  if (!encode_analysis_fact(fact, encoded, error))
    return false;
  out = digest_bytes(encoded);
  return true;
}

FactDigest sha256_bytes(const std::vector<uint8_t> &bytes)
{
  return digest_bytes(bytes);
}

bool payload_less(const FactPayload &lhs, const FactPayload &rhs)
{
  std::vector<uint8_t> left;
  std::vector<uint8_t> right;
  std::string left_error;
  std::string right_error;
  if (!encode_payload(lhs, left, &left_error))
    left = invalid_sort_key(left_error);
  if (!encode_payload(rhs, right, &right_error))
    right = invalid_sort_key(right_error);
  return left < right;
}

bool evidence_less(const Evidence &lhs, const Evidence &rhs)
{
  std::vector<uint8_t> left;
  std::vector<uint8_t> right;
  std::string left_error;
  std::string right_error;
  if (!encode_evidence(lhs, left, &left_error))
    left = invalid_sort_key(left_error);
  if (!encode_evidence(rhs, right, &right_error))
    right = invalid_sort_key(right_error);
  return left < right;
}

bool analysis_fact_less(const AnalysisFact &lhs, const AnalysisFact &rhs)
{
  if (payload_less(lhs.payload, rhs.payload))
    return true;
  if (payload_less(rhs.payload, lhs.payload))
    return false;
  return evidence_less(lhs.evidence, rhs.evidence);
}

bool payload_equal(const FactPayload &lhs, const FactPayload &rhs)
{
  return !payload_less(lhs, rhs) && !payload_less(rhs, lhs);
}

bool evidence_equal(const Evidence &lhs, const Evidence &rhs)
{
  return !evidence_less(lhs, rhs) && !evidence_less(rhs, lhs);
}

} // namespace analysis
} // namespace viy
