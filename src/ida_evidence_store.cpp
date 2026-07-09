#include "ida_evidence_store.hpp"

#include <algorithm>

#include <pro.h>
#include <netnode.hpp>

namespace viy {

namespace {

constexpr const char kEvidenceNode[] = "$ viy:evidence:v1";
constexpr const char kEvidenceSlotA[] = "$ viy:evidence:v1:a";
constexpr const char kEvidenceSlotB[] = "$ viy:evidence:v1:b";
constexpr uchar kBlobTag = 'V';
constexpr nodeidx_t kActiveIndex = 0;
constexpr nodeidx_t kSlotA = 1;
constexpr nodeidx_t kSlotB = 2;
constexpr nodeidx_t kSlotBlobIndex = 0;

const char *slot_node_name(nodeidx_t slot)
{
  return slot == kSlotA ? kEvidenceSlotA : kEvidenceSlotB;
}

bool read_slot(nodeidx_t slot,
               std::vector<uint8_t> &out, std::string &error)
{
  netnode node;
  const char *name = slot_node_name(slot);
  if ( !node.exist(name) )
  {
    error = "viy evidence slot netnode not found";
    return false;
  }
  node.create(name);
  bytevec_t bytes;
  const ssize_t size = node.getblob(&bytes, kSlotBlobIndex, kBlobTag);
  if ( size < 0 )
  {
    error = "viy evidence blob not found";
    return false;
  }
  if ( size_t(size) != bytes.size() )
  {
    error = "viy evidence blob size mismatch";
    return false;
  }
  out.assign(bytes.begin(), bytes.end());
  return true;
}

// Compatibility with the briefly-used adjacent-index layout. Large netnode
// blobs occupy multiple supval indices, so slots 1 and 2 could overlap; read
// whichever complete legacy envelope still validates and migrate it.
bool read_legacy_slot(netnode &node, nodeidx_t slot,
                      std::vector<uint8_t> &out, std::string &error)
{
  bytevec_t bytes;
  const ssize_t size = node.getblob(&bytes, slot, kBlobTag);
  if ( size < 0 || size_t(size) != bytes.size() )
  {
    error = "legacy viy evidence slot not found";
    return false;
  }
  out.assign(bytes.begin(), bytes.end());
  return true;
}

bool stage_slot(nodeidx_t slot, const std::vector<uint8_t> &blob,
                std::string &error)
{
  netnode node;
  const char *name = slot_node_name(slot);
  if ( node.exist(name) )
    node.create(name); // attach; create() may report false for an existing node
  else if ( !node.create(name) )
  {
    error = "could not create viy evidence staging slot";
    return false;
  }
  if ( !node.setblob(blob.data(), blob.size(), kSlotBlobIndex, kBlobTag) )
  {
    error = "could not write viy evidence staging slot";
    return false;
  }
  return true;
}

} // namespace

bool IdaEvidenceAdapter::read_blob(std::vector<uint8_t> &out, std::string &error) const
{
  out.clear();
  netnode node;
  if ( !node.exist(kEvidenceNode) )
  {
    error = "viy evidence netnode not found";
    return false;
  }
  node.create(kEvidenceNode);
  nodeidx_t active = node.altval(kActiveIndex);
  auto valid_slot = [&](nodeidx_t slot, std::vector<uint8_t> &bytes,
                        std::string &why) -> bool
  {
    if ( !read_slot(slot, bytes, why) )
      return false;
    analysis::EvidenceStore decoded;
    return analysis::EvidenceStore::deserialize(bytes, decoded, &why);
  };

  if ( active != kSlotA && active != kSlotB )
  {
    // A torn/corrupt commit marker must not make two intact envelopes
    // unreachable.  If both slots validate, merge them: evidence union is the
    // only recovery rule that cannot silently discard an observation.
    std::vector<uint8_t> a_bytes;
    std::vector<uint8_t> b_bytes;
    std::string a_error;
    std::string b_error;
    const bool a_valid = valid_slot(kSlotA, a_bytes, a_error);
    const bool b_valid = valid_slot(kSlotB, b_bytes, b_error);
    if ( !a_valid && !b_valid )
    {
      error = "viy evidence commit marker invalid; slot A invalid: " + a_error
            + "; slot B invalid: " + b_error;
      return false;
    }
    if ( a_valid && b_valid )
    {
      analysis::EvidenceStore recovered;
      analysis::EvidenceStore other;
      std::string decode_error;
      if ( !analysis::EvidenceStore::deserialize(a_bytes, recovered, &decode_error)
        || !analysis::EvidenceStore::deserialize(b_bytes, other, &decode_error) )
      {
        error = "validated evidence slot failed second decode: " + decode_error;
        return false;
      }
      recovered.merge(other);
      if ( !recovered.serialize(out, &error) )
        return false;
      // Repair through the same stage-then-marker ordering used by writes.
      if ( !stage_slot(kSlotA, out, error) )
      {
        out.clear();
        return false;
      }
      node.altset(kActiveIndex, kSlotA);
      return true;
    }
    out = a_valid ? std::move(a_bytes) : std::move(b_bytes);
    node.altset(kActiveIndex, a_valid ? kSlotA : kSlotB);
    return true;
  }

  std::string active_error;
  if ( valid_slot(active, out, active_error) )
    return true;

  const nodeidx_t fallback = active == kSlotA ? kSlotB : kSlotA;
  std::string fallback_error;
  if ( valid_slot(fallback, out, fallback_error) )
  {
    // Repair the commit marker only after a complete SHA/schema validation.
    node.altset(kActiveIndex, fallback);
    return true;
  }

  // One-time migration from the former same-node layout. Validate the complete
  // envelope before copying it to a non-overlapping slot node.
  for ( nodeidx_t legacy : { active, fallback } )
  {
    std::vector<uint8_t> legacy_bytes;
    std::string legacy_error;
    analysis::EvidenceStore decoded;
    if ( read_legacy_slot(node, legacy, legacy_bytes, legacy_error)
      && analysis::EvidenceStore::deserialize(legacy_bytes, decoded, &legacy_error)
      && stage_slot(legacy, legacy_bytes, legacy_error) )
    {
      node.altset(kActiveIndex, legacy);
      out = std::move(legacy_bytes);
      return true;
    }
  }
  error = "active evidence slot invalid: " + active_error
        + "; fallback invalid: " + fallback_error;
  out.clear();
  return false;
}

bool IdaEvidenceAdapter::write_blob(const std::vector<uint8_t> &blob, std::string &error)
{
  if ( blob.empty() )
  {
    error = "refusing to persist an empty evidence envelope";
    return false;
  }
  analysis::EvidenceStore decoded;
  if ( !analysis::EvidenceStore::deserialize(blob, decoded, &error) )
  {
    error = "refusing to persist an invalid evidence envelope: " + error;
    return false;
  }
  netnode node;
  if ( node.exist(kEvidenceNode) )
    node.create(kEvidenceNode);
  else if ( !node.create(kEvidenceNode) )
  {
    error = "could not create viy evidence netnode";
    return false;
  }
  const nodeidx_t active = node.altval(kActiveIndex);
  const nodeidx_t next = active == kSlotA ? kSlotB : kSlotA;
  if ( !stage_slot(next, blob, error) )
    return false;

  // Verify the complete staging value before committing its slot number. A
  // database interruption can therefore leave either the old or new envelope,
  // never a committed partial serialization.
  std::vector<uint8_t> verify;
  analysis::EvidenceStore verified;
  if ( !read_slot(next, verify, error) || verify != blob
    || !analysis::EvidenceStore::deserialize(verify, verified, &error) )
  {
    netnode failed;
    if ( failed.exist(slot_node_name(next)) )
    {
      failed.create(slot_node_name(next));
      failed.kill();
    }
    if ( error.empty() )
      error = "viy evidence staging verification failed";
    return false;
  }
  if ( !node.altset(kActiveIndex, next) )
  {
    netnode failed;
    if ( failed.exist(slot_node_name(next)) )
    {
      failed.create(slot_node_name(next));
      failed.kill();
    }
    error = "could not commit viy evidence slot";
    return false;
  }
  // Retain the previous committed slot. The next write replaces it only after
  // the other slot has become the validated active envelope.
  return true;
}

bool IdaEvidenceAdapter::erase(std::string *error)
{
  if ( error != nullptr )
    error->clear();
  netnode node;
  if ( node.exist(kEvidenceNode) )
  {
    node.create(kEvidenceNode);
    node.delblob(kSlotA, kBlobTag); // legacy layout cleanup
    node.delblob(kSlotB, kBlobTag);
    node.altdel(kActiveIndex);
    node.kill();
  }
  for ( nodeidx_t slot : { kSlotA, kSlotB } )
  {
    netnode separate;
    if ( separate.exist(slot_node_name(slot)) )
    {
      separate.create(slot_node_name(slot));
      separate.kill();
    }
  }
  return true;
}

} // namespace viy
