// Phase 18-A: target-eNB admission for S1-based connected-mode handover.
//
// Admission is the target eNB's decision about whether it will accept the
// bearers the MME asked it to take over. It is deliberately separate from
// commitment. Decoding a Handover Request and evaluating its admission allocates
// nothing: no local S1-U TEID is reserved or bound, no forwarding tunnel is
// created, no bearer is established or released and no UE session starts. The
// result is a plan that names what the target would do if the handover were
// committed, and the plan's transport endpoints are unbound by construction.
//
// Bearer role is not derivable from QCI and not derivable from the position of
// an E-RAB in a list. S1AP's E-RABToBeSetupListHOReq states an E-RAB identity,
// an SGW transport endpoint and QoS, and nothing more. The role of each bearer
// therefore comes from the network's own statement of the EPS session, supplied
// here as a BearerRoleBinding per E-RAB identity. An E-RAB with no binding is
// refused rather than classified.

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "codec.hpp"

namespace lte::enb::s1ap
{

enum class BearerRole : uint8_t
{
    DEFAULT = 0,
    DEDICATED = 1
};
const char *ToString(BearerRole role);

// The network's own statement of what one bearer is. A dedicated bearer names
// the default bearer it is linked to; a default bearer does not.
struct BearerRoleBinding
{
    uint8_t erabId{};
    BearerRole role{BearerRole::DEFAULT};
    std::optional<uint8_t> linkedDefaultErabId;
    uint8_t qci{};
    uint8_t priorityLevel{};
    bool preemptionCapability{};
    bool preemptionVulnerability{};
};

// The source eNB as the Handover Request establishes it. The Handover Request
// itself names no source eNB identity: id-SourceID is declared in TS 36.413 but
// referenced by no handover information element set, and no message in this
// codec emits or requires it. The source identity is therefore carried here,
// from the S1 association the request arrived on, and its absence is refused.
struct SourceContext
{
    EnbIdentity identity;
    bool identityKnown{false};
};

// The target eNB: the identity it answers under, the local S1-U address it
// would serve on, and the integrity and encryption algorithms it supports.
struct TargetContext
{
    EnbIdentity identity;
    std::array<uint8_t, 4> s1uAddress{};
    std::array<uint8_t, 2> encryptionAlgorithms{};
    std::array<uint8_t, 2> integrityAlgorithms{};
};

// A transport endpoint the target would use if the handover were committed.
// Admission fills in the local address and leaves the TEID unassigned and the
// endpoint unbound. A bound endpoint is created by a commit step that this
// phase does not implement.
struct TargetTransportEndpoint
{
    std::array<uint8_t, 4> address{};
    std::array<uint8_t, 4> teid{};
    bool bound{false};
};

// One bearer the target is willing to take over. The role, the linked default
// and the QoS are the network's, carried across unchanged.
struct AdmittedBearer
{
    uint8_t erabId{};
    BearerRole role{BearerRole::DEFAULT};
    std::optional<uint8_t> linkedDefaultErabId;
    uint8_t qci{};
    uint8_t priorityLevel{};
    bool preemptionCapability{};
    bool preemptionVulnerability{};
    std::optional<GbrQos> gbr;
    std::array<uint8_t, 4> sgwAddress{};
    std::array<uint8_t, 4> sgwTeid{};
    TargetTransportEndpoint targetTransport;
};

// Why the target refused. Each value maps to one Cause the standard names, so a
// refusal can be reported to the MME without inventing one.
enum class AdmissionRefusal : uint8_t
{
    UNKNOWN_HANDOVER_TYPE,
    UNSUPPORTED_TARGET,
    SOURCE_CONTEXT_UNKNOWN,
    BEARER_ROLE_UNCONFIRMED,
    BEARER_QOS_MISMATCH,
    DUPLICATE_ERAB_ID,
    EMPTY_BEARER_SET,
    LINKED_DEFAULT_MISSING,
    DEDICATED_WITHOUT_LINK,
    SECURITY_ALGORITHMS_NOT_SUPPORTED,
    TRANSPORT_ADDRESS_ABSENT
};
const char *ToString(AdmissionRefusal refusal);

struct AdmissionRefusalRecord
{
    AdmissionRefusal refusal{};
    std::string detail;
    std::string causeCategory{"radioNetwork"};
    int causeValue{0};
};

struct HandoverAdmission
{
    bool admitted{false};
    HandoverType handoverType{HandoverType::INTRA_LTE};
    EnbIdentity source;
    EnbIdentity target;
    // Default bearers first, then dedicated bearers, each group in the order the
    // request listed them. The order is a readiness order, not the wire order.
    std::vector<AdmittedBearer> bearers;
    TransparentContainer sourceToTarget;
    std::array<uint8_t, 32> nextHopParameter{};
    uint8_t nextHopChainingCount{};
    std::optional<AdmissionRefusalRecord> refusal;

    // True when any planned bearer endpoint is bound. Admission must never
    // produce a true here: an unvalidated decoded request is not authority to
    // create a forwarding tunnel.
    [[nodiscard]] bool holdsTransportResources() const;
};

// Evaluates a decoded Handover Request against the source and target contexts
// and the network's bearer roles. Pure: it reads only its arguments and
// touches no registry, allocator, bearer or UE state.
HandoverAdmission EvaluateHandoverAdmission(const HandoverRequest &request, const SourceContext &source,
                                            const TargetContext &target,
                                            const std::vector<BearerRoleBinding> &roles);

// A Handover Required names its target in TargetID; a Handover Request does
// not. This checks a named target against the receiving eNB and reports the
// reason it is refused, or nothing when the two agree.
std::optional<AdmissionRefusalRecord> CheckNamedTarget(const EnbIdentity &named, const TargetContext &target);

// The Handover Failure the MME would be sent for a refused admission. The
// failure carries no eNB-UE-S1AP-ID, because the target binds none before it
// admits.
HandoverFailure RefusalAsHandoverFailure(const HandoverAdmission &admission, uint32_t mmeUeS1apId);

// One transport endpoint that a commit step actually bound. Admission never
// produces these: they come from the local S1-U allocator at commit time, and
// this phase implements no commit.
struct CommittedTransport
{
    uint8_t erabId{};
    std::array<uint8_t, 4> address{};
    std::array<uint8_t, 4> teid{};
};

// Builds the Handover Request Acknowledge for an admitted handover whose
// transport a commit step has bound. The committed endpoints are supplied by
// that step; this function invents no address and no TEID, and refuses an
// admission that has no commit behind it.
HandoverRequestAcknowledge BuildHandoverRequestAcknowledge(const HandoverAdmission &admission,
                                                           uint32_t mmeUeS1apId, uint32_t enbUeS1apId,
                                                           const std::vector<CommittedTransport> &committed);

} // namespace lte::enb::s1ap
