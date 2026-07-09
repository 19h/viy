/* IDA netnode persistence for the producer-neutral evidence ledger. */
#pragma once

#include "evidence_store.hpp"

namespace viy {

class IdaEvidenceAdapter final : public analysis::EvidencePersistenceAdapter
{
public:
  bool read_blob(std::vector<uint8_t> &out, std::string &error) const override;
  bool write_blob(const std::vector<uint8_t> &blob, std::string &error) override;
  bool erase(std::string *error = nullptr);
};

} // namespace viy
