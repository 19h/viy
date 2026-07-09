/*
 * rax_loader.cpp — dlopen + dlsym resolution of the rax C ABI, behind an ABI gate.
 *
 * No IDA headers here: this translation unit is pure host C++ and could be unit
 * tested headless against a stub librax. It never throws and never aborts; every
 * failure path leaves the API unavailable with a precise reason string.
 */
#include "rax_loader.hpp"

#include <dlfcn.h>

#include <cstdlib>
#include <mutex>
#include <string>

#if defined(__APPLE__)
#  include <mach-o/dyld.h> // _NSGetExecutablePath
#elif defined(__linux__)
#  include <unistd.h>      // readlink
#endif

namespace viy {

namespace {

std::string g_reason;

// Candidate paths to try, in order. A VIY_RAX_PATH override wins; otherwise we
// try a bare name (resolved via the platform loader search path), then a path
// next to this shared object (drop librax beside viy.dylib for zero-config use).
#if defined(__APPLE__)
constexpr const char *kBareName = "librax.dylib";
#elif defined(_WIN32)
constexpr const char *kBareName = "rax.dll";
#else
constexpr const char *kBareName = "librax.so";
#endif

// Resolve the directory containing this plugin binary, so we can look for a
// sibling librax. Returns empty on failure.
std::string self_dir()
{
  Dl_info info{};
  if ( dladdr(reinterpret_cast<const void *>(&self_dir), &info) == 0
    || info.dli_fname == nullptr )
  {
    return {};
  }
  std::string path = info.dli_fname;
  auto slash = path.find_last_of("/\\");
  if ( slash == std::string::npos )
    return {};
  return path.substr(0, slash + 1); // keep trailing separator
}

// A resource directory named after this plugin, next to it: e.g. for a plugin
// at …/plugins/viy.dylib this returns …/plugins/viy/ . librax is installed there
// so IDA (which scans …/plugins/*.dylib for plugins) never tries to load it.
std::string companion_dir()
{
  Dl_info info{};
  if ( dladdr(reinterpret_cast<const void *>(&companion_dir), &info) == 0
    || info.dli_fname == nullptr )
  {
    return {};
  }
  std::string p = info.dli_fname;
  auto slash = p.find_last_of("/\\");
  std::string dir  = slash == std::string::npos ? std::string() : p.substr(0, slash + 1);
  std::string file = slash == std::string::npos ? p : p.substr(slash + 1);
  auto dot = file.find_last_of('.');
  std::string stem = dot == std::string::npos ? file : file.substr(0, dot);
  if ( stem.empty() )
    return {};
  return dir + stem + "/"; // …/plugins/viy/
}

// Directory of the host executable (the IDA binary). Lets librax sit in the
// "IDA folder" and still be found. Empty on failure / unsupported platforms.
std::string main_exe_dir()
{
  std::string p;
#if defined(__APPLE__)
  char buf[4096];
  uint32_t sz = sizeof(buf);
  if ( _NSGetExecutablePath(buf, &sz) != 0 )
    return {};
  p = buf;
#elif defined(__linux__)
  char buf[4096];
  ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
  if ( n <= 0 )
    return {};
  buf[n] = '\0';
  p = buf;
#else
  return {};
#endif
  auto slash = p.find_last_of("/\\");
  if ( slash == std::string::npos )
    return {};
  return p.substr(0, slash + 1);
}

void *try_dlopen()
{
  const int mode = RTLD_NOW | RTLD_LOCAL;

  if ( const char *env = std::getenv("VIY_RAX_PATH"); env != nullptr && env[0] != '\0' )
  {
    if ( void *h = dlopen(env, mode) )
      return h;
  }

  if ( void *h = dlopen(kBareName, mode) )
    return h;

  // In a companion resource dir (…/plugins/viy/librax.dylib) — the recommended
  // install layout, since IDA won't try to load it as a plugin from there.
  if ( std::string dir = companion_dir(); !dir.empty() )
  {
    std::string p = dir + kBareName;
    if ( void *h = dlopen(p.c_str(), mode) )
      return h;
  }

  // Next to the viy plugin binary (…/plugins/librax.dylib).
  if ( std::string dir = self_dir(); !dir.empty() )
  {
    std::string sib = dir + kBareName;
    if ( void *h = dlopen(sib.c_str(), mode) )
      return h;
  }

  // In the IDA folder (next to the ida/ida64 executable).
  if ( std::string dir = main_exe_dir(); !dir.empty() )
  {
    std::string sib = dir + kBareName;
    if ( void *h = dlopen(sib.c_str(), mode) )
      return h;
  }

  return nullptr;
}

// Resolve every symbol and gate on the ABI version. Fills `out`; returns true on
// full success. On any failure sets g_reason and closes the handle.
bool resolve(void *h, RaxApi *out)
{
#define X(field, sym)                                                     \
  out->field = reinterpret_cast<decltype(&sym)>(dlsym(h, #sym));          \
  if ( out->field == nullptr )                                            \
  {                                                                       \
    g_reason = std::string("librax missing symbol ") + #sym;              \
    *out = RaxApi{};                                                      \
    dlclose(h);                                                           \
    return false;                                                         \
  }
  VIY_RAX_FUNCS(X)
#undef X

  // ABI gate: MAJOR must match exactly; MINOR must cover the EMULATION surface
  // viy requires (introduced in rax 1.1). The static decoder arrived in 1.2 and
  // is resolved separately below as OPTIONAL, so viy still runs (emulation only)
  // against an older librax.
  static const uint32_t kRequiredMinor = 1;
  uint32_t maj = 0, min = 0, patch = 0;
  out->version(&maj, &min, &patch);
  if ( maj != RAX_API_MAJOR || min < kRequiredMinor )
  {
    g_reason = "librax ABI incompatible (viy needs "
             + std::to_string((unsigned)RAX_API_MAJOR) + "."
             + std::to_string((unsigned)kRequiredMinor) + "+, found "
             + std::to_string(maj) + "." + std::to_string(min) + ")";
    *out = RaxApi{};
    dlclose(h);
    return false;
  }

  // Optional: the static decoder (rax >= 1.2). If absent, out->decode stays null
  // and viy simply skips its static-decode pass.
  out->decode = reinterpret_cast<decltype(&rax_decode)>(dlsym(h, "rax_decode"));

  return true;
}

const RaxApi *load_once()
{
  static RaxApi api;
  static bool ok = false;
  static std::once_flag flag;
  std::call_once(flag, [] {
    void *h = try_dlopen();
    if ( h == nullptr )
    {
      g_reason = "librax not found (set VIY_RAX_PATH or place it next to the plugin)";
      return;
    }
    ok = resolve(h, &api); // keeps the handle open for the process lifetime on success
  });
  return ok ? &api : nullptr;
}

} // namespace

const RaxApi *rax_load() { return load_once(); }

const char *rax_unavailable_reason() { return g_reason.c_str(); }

} // namespace viy
