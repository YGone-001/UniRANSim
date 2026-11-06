// Phase 18-A: target-eNB admission for S1-based connected-mode handover.
//
// Everything here is a pure evaluation over its arguments. There is no registry
// include in this file and there must never be one: a decoded Handover Request
// is not authority to create a forwarding tunnel, reserve or bind a local S1-U
// TEID, retire one, release a bearer or start a UE session.

#include "handover_admission.hpp"

#include <algorithm>
#include <set>

namespace lte::enb::s1ap
{

const char *ToString(BearerRole role)
{
    switch (role)
    {
    case BearerRole::DEFAULT:
        return "default";
    case BearerRole::DEDICATED:
        return "dedicated";
    }
    return "unknown";
}

const char *ToString(AdmissionRefusal refusal)
{
    switch (refusal)
    {
    case AdmissionRefusal::UNKNOWN_HANDOVER_TYPE:
        return "unknown-handover-type";
    case AdmissionRefusal::UNSUPPORTED_TARGET:
        return "unsupported-target";
    case AdmissionRefusal::SOURCE_CONTEXT_UNKNOWN:
        return "source-context-unknown";
    case AdmissionRefusal::BEARER_ROLE_UNCONFIRMED:
        return "bearer-role-unconfirmed";
    case AdmissionRefusal::BEARER_QOS_MISMATCH:
        return "bearer-qos-mismatch";
    case AdmissionRefusal::DUPLICATE_ERAB_ID:
        return "duplicate-erab-id";
    case AdmissionRefusal::EMPTY_BEARER_SET:
        return "empty-bearer-set";
    case AdmissionRefusal::LINKED_DEFAULT_MISSING:
        return "linked-default-missing";
    case AdmissionRefusal::DEDICATED_WITHOUT_LINK:
        return "dedicated-without-link";
    case AdmissionRefusal::SECURITY_ALGORITHMS_NOT_SUPPORTED:
        return "security-algorithms-not-supported";
    case AdmissionRefusal::TRANSPORT_ADDRESS_ABSENT:
        return "transport-address-absent";
    }
    return "unknown";
}

namespace
{

// Cause values are the TS 36.413 CauseRadioNetwork enumeration indices, which
// is what WriteCause encodes. Nothing here invents a value.
AdmissionRefusalRecord Refuse(AdmissionRefusal refusal, const std::string &detail, int causeValue)
{
    return AdmissionRefusalRecord{refusal, detail, "radioNetwork", causeValue};
}

constexpr int CauseHoFailureInTarget = 6;
constexpr int CauseHoTargetNotAllowed = 7;
constexpr int CauseCellNotAvailable = 10;
constexpr int CauseNoRadioResourcesInTarget = 12;
constexpr int CauseInvalidQosCombination = 27;
constexpr int CauseEncryptionAlgorithmsNotSupported = 32;
constexpr int CauseUnknownErabId = 30;
constexpr int CauseMultipleErabIdInstances = 31;

bool AlgorithmsIntersect(const std::array<uint8_t, 2> &a, const std::array<uint8_t, 2> &b)
{
    for (size_t i = 0; i < a.size() && i < b.size(); ++i)
    {
        if ((a[i] & b[i]) != 0)
            return true;
    }
    return false;
}

bool SamePlmn(const Plmn &a, const Plmn &b)
{
    return a.mcc == b.mcc && a.mnc == b.mnc;
}

bool SameEnbIdentity(const EnbIdentity &a, const EnbIdentity &b)
{
    return a.enbId == b.enbId && a.tac == b.tac && SamePlmn(a.plmn, b.plmn);
}

bool SameQos(const ErabQos &a, const BearerRoleBinding &b)
{
    return a.qci == b.qci && a.priorityLevel == b.priorityLevel &&
           a.preemptionCapability == b.preemptionCapability &&
           a.preemptionVulnerability == b.preemptionVulnerability;
}

} // namespace

bool HandoverAdmission::holdsTransportResources() const
{
    return std::any_of(bearers.begin(), bearers.end(),
                       [](const AdmittedBearer &bearer) { return bearer.targetTransport.bound; });
}

HandoverAdmission EvaluateHandoverAdmission(const HandoverRequest &request, const SourceContext &source,
                                            const TargetContext &target,
                                            const std::vector<BearerRoleBinding> &roles)
{
    HandoverAdmission result{};
    result.handoverType = request.handoverType;
    result.source = source.identity;
    result.target = target.identity;
    result.sourceToTarget = request.sourceToTarget;
    result.nextHopParameter = request.securityContext.nextHopParameter;
    result.nextHopChainingCount = request.securityContext.nextHopChainingCount;

    auto fail = [&](AdmissionRefusal refusal, const std::string &detail, int causeValue) {
        result.admitted = false;
        result.bearers.clear();
        result.refusal = Refuse(refusal, detail, causeValue);
        return result;
    };

    // Only an intra-LTE handover is implemented. The four other root
    // HandoverType values are inter-RAT and the two extension values are 5GS.
    if (request.handoverType != HandoverType::INTRA_LTE)
        return fail(AdmissionRefusal::UNKNOWN_HANDOVER_TYPE,
                    std::string("Unsupported HandoverType ") + ToString(request.handoverType),
                    CauseHoFailureInTarget);

    // A Handover Request names no target: the target is the eNB that received
    // it. The receiving eNB must still be a coherent target, and the cell must
    // be one it can serve on.
    if (target.identity.enbId == 0 || target.identity.plmn.mcc.empty())
        return fail(AdmissionRefusal::UNSUPPORTED_TARGET, "The target eNB has no identity",
                    CauseHoTargetNotAllowed);
    if (target.identity.tac == 0)
        return fail(AdmissionRefusal::UNSUPPORTED_TARGET, "The target cell is not available",
                    CauseCellNotAvailable);

    // The Handover Request carries no source eNB identity. The source is what
    // the S1 association says it is, and a request whose source cannot be
    // established is refused rather than assumed.
    if (!source.identityKnown)
        return fail(AdmissionRefusal::SOURCE_CONTEXT_UNKNOWN,
                    "The Handover Request arrived with no established source eNB identity",
                    CauseHoFailureInTarget);
    if (source.identity.enbId == 0)
        return fail(AdmissionRefusal::SOURCE_CONTEXT_UNKNOWN,
                    "The source eNB has no identity", CauseHoFailureInTarget);
    if (source.identity.enbId == target.identity.enbId)
        return fail(AdmissionRefusal::UNSUPPORTED_TARGET,
                    "The source and the target are the same eNB", CauseHoTargetNotAllowed);

    // At least one mutually supported integrity and encryption algorithm, or
    // the UE cannot be protected on the target. This is the target's own
    // capability against the capabilities the MME sent; nothing here invents a
    // key or a capability.
    if (!AlgorithmsIntersect(request.encryptionAlgorithms, target.encryptionAlgorithms) ||
        !AlgorithmsIntersect(request.integrityAlgorithms, target.integrityAlgorithms))
        return fail(AdmissionRefusal::SECURITY_ALGORITHMS_NOT_SUPPORTED,
                    "No mutually supported integrity or encryption algorithm",
                    CauseEncryptionAlgorithmsNotSupported);

    if (request.erabs.empty())
        return fail(AdmissionRefusal::EMPTY_BEARER_SET,
                    "The Handover Request carries no E-RAB to set up", CauseNoRadioResourcesInTarget);

    // The role of each bearer comes from the network's statement of the session.
    // An E-RAB the network has not classified is refused: it is not classified
    // by its QCI and not by its position in the list.
    std::set<uint8_t> seenErabs;
    std::set<uint8_t> admittedDefaults;
    for (const auto &erab : request.erabs)
    {
        if (!seenErabs.insert(erab.erabId).second)
            return fail(AdmissionRefusal::DUPLICATE_ERAB_ID,
                        "The Handover Request names E-RAB " + std::to_string(erab.erabId) + " twice",
                        CauseMultipleErabIdInstances);
        if (erab.erabId == 0)
            return fail(AdmissionRefusal::BEARER_ROLE_UNCONFIRMED,
                        "The Handover Request names E-RAB identity zero", CauseUnknownErabId);
    }

    std::vector<AdmittedBearer> planned;
    planned.reserve(request.erabs.size());

    for (const int groupPass : {0, 1})
    {
        const auto wantedRole = groupPass == 0 ? BearerRole::DEFAULT : BearerRole::DEDICATED;
        for (const auto &erab : request.erabs)
        {
            const auto binding = std::find_if(roles.begin(), roles.end(),
                                              [&](const BearerRoleBinding &role) {
                                                  return role.erabId == erab.erabId;
                                              });
            if (binding == roles.end())
                return fail(AdmissionRefusal::BEARER_ROLE_UNCONFIRMED,
                            "The network has not stated a bearer role for E-RAB " +
                                std::to_string(erab.erabId),
                            CauseUnknownErabId);
            if (binding->role != wantedRole)
                continue;

            // The QoS the MME sent for this E-RAB must be the QoS the network
            // already negotiated for it. A disagreement is not resolved here by
            // preferring either side.
            if (!SameQos(erab.qos, *binding))
                return fail(AdmissionRefusal::BEARER_QOS_MISMATCH,
                            "The Handover Request disagrees with the negotiated QoS of E-RAB " +
                                std::to_string(erab.erabId),
                            CauseInvalidQosCombination);
            if (erab.qos.gbr.has_value() && erab.qos.qci > 4)
                return fail(AdmissionRefusal::BEARER_QOS_MISMATCH,
                            "A non-GBR QCI must not carry GBR QoS Information for E-RAB " +
                                std::to_string(erab.erabId),
                            CauseInvalidQosCombination);

            if (wantedRole == BearerRole::DEDICATED && !binding->linkedDefaultErabId.has_value())
                return fail(AdmissionRefusal::DEDICATED_WITHOUT_LINK,
                            "Dedicated E-RAB " + std::to_string(erab.erabId) + " names no default bearer",
                            CauseInvalidQosCombination);

            AdmittedBearer admitted{};
            admitted.erabId = erab.erabId;
            admitted.role = binding->role;
            admitted.linkedDefaultErabId = binding->linkedDefaultErabId;
            admitted.qci = erab.qos.qci;
            admitted.priorityLevel = erab.qos.priorityLevel;
            admitted.preemptionCapability = erab.qos.preemptionCapability;
            admitted.preemptionVulnerability = erab.qos.preemptionVulnerability;
            admitted.gbr = erab.qos.gbr;
            admitted.sgwAddress = erab.sgwAddress;
            admitted.sgwTeid = erab.sgwTeid;
            // The plan names the local address the target would serve on. The
            // TEID is left unassigned and the endpoint unbound: admission is not
            // commitment and creates no forwarding tunnel.
            admitted.targetTransport.address = target.s1uAddress;
            planned.push_back(admitted);
        }
    }

    // Readiness is ordered: the default bearers come first whatever order the
    // E-RABs arrived in, and a dedicated bearer is only ready after the default
    // it is linked to.
    for (const auto &bearer : planned)
    {
        if (bearer.role == BearerRole::DEFAULT)
            admittedDefaults.insert(bearer.erabId);
    }
    for (const auto &bearer : planned)
    {
        if (bearer.role != BearerRole::DEDICATED)
            continue;
        const auto linked = bearer.linkedDefaultErabId.value_or(0);
        if (admittedDefaults.count(linked) == 0)
            return fail(AdmissionRefusal::LINKED_DEFAULT_MISSING,
                        "Dedicated E-RAB " + std::to_string(bearer.erabId) +
                            " is linked to default E-RAB " + std::to_string(linked) +
                            ", which is not admitted",
                        CauseInvalidQosCombination);
    }

    if (admittedDefaults.empty())
        return fail(AdmissionRefusal::EMPTY_BEARER_SET,
                    "The Handover Request carries no default bearer", CauseNoRadioResourcesInTarget);

    result.bearers = std::move(planned);
    result.admitted = true;
    result.refusal.reset();
    return result;
}

HandoverFailure RefusalAsHandoverFailure(const HandoverAdmission &admission, uint32_t mmeUeS1apId)
{
    if (admission.admitted || !admission.refusal.has_value())
        throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                              "Only a refused admission has a Handover Failure");
    HandoverFailure failure{};
    failure.mmeUeS1apId = mmeUeS1apId;
    failure.causeCategory = admission.refusal->causeCategory;
    failure.causeValue = admission.refusal->causeValue;
    return failure;
}

HandoverRequestAcknowledge BuildHandoverRequestAcknowledge(const HandoverAdmission &admission,
                                                           uint32_t mmeUeS1apId, uint32_t enbUeS1apId,
                                                           const std::vector<CommittedTransport> &committed)
{
    if (!admission.admitted)
        throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                              "A refused admission has no Handover Request Acknowledge");
    if (admission.bearers.empty())
        throw HandoverRefused(HandoverRefusal::UNSUPPORTED_ERAB_LIST,
                              "An admitted handover with no bearer has nothing to acknowledge");
    // Admission is a plan and holds no transport. Acknowledging a bearer claims
    // a tunnel exists, so every admitted bearer must have a transport endpoint a
    // commit step actually bound. Nothing here fills one in.
    if (committed.size() != admission.bearers.size())
        throw HandoverRefused(HandoverRefusal::UNSUPPORTED_ERAB_LIST,
                              "The committed transport set does not cover the admitted bearers");

    HandoverRequestAcknowledge message{};
    message.mmeUeS1apId = mmeUeS1apId;
    message.enbUeS1apId = enbUeS1apId;
    std::set<uint8_t> seen;
    for (const auto &bearer : admission.bearers)
    {
        const auto match = std::find_if(committed.begin(), committed.end(),
                                        [&](const CommittedTransport &item) {
                                            return item.erabId == bearer.erabId;
                                        });
        if (match == committed.end())
            throw HandoverRefused(HandoverRefusal::UNSUPPORTED_ERAB_LIST,
                                  "No committed transport for E-RAB " + std::to_string(bearer.erabId));
        if (!seen.insert(bearer.erabId).second)
            throw HandoverRefused(HandoverRefusal::UNSUPPORTED_ERAB_LIST,
                                  "The admitted bearers name E-RAB " + std::to_string(bearer.erabId) +
                                      " twice");
        if (match->address != bearer.targetTransport.address)
            throw HandoverRefused(HandoverRefusal::UNSUPPORTED_ERAB_LIST,
                                  "The committed transport for E-RAB " + std::to_string(bearer.erabId) +
                                      " is not on the target's S1-U address");
        if (match->teid == std::array<uint8_t, 4>{})
            throw HandoverRefused(HandoverRefusal::UNSUPPORTED_ERAB_LIST,
                                  "The committed transport for E-RAB " + std::to_string(bearer.erabId) +
                                      " has no TEID");

        ErabAdmittedItem item{};
        item.erabId = bearer.erabId;
        item.transportLayerAddress = match->address;
        item.gtpTeid = match->teid;
        message.admitted.push_back(item);
    }
    message.targetToSource = admission.sourceToTarget;
    return message;
}

std::optional<AdmissionRefusalRecord> CheckNamedTarget(const EnbIdentity &named, const TargetContext &target)
{
    // A Handover Required names its target in TargetID; a Handover Request does
    // not. The named target has to be the eNB that received the message, or the
    // request is not one this eNB may prepare against.
    if (named.enbId == 0 || named.plmn.mcc.empty())
        return Refuse(AdmissionRefusal::UNSUPPORTED_TARGET, "The named target has no identity",
                      CauseHoTargetNotAllowed);
    if (named.tac == 0)
        return Refuse(AdmissionRefusal::UNSUPPORTED_TARGET, "The named target has no tracking area",
                      CauseHoTargetNotAllowed);
    if (!SameEnbIdentity(named, target.identity))
        return Refuse(AdmissionRefusal::UNSUPPORTED_TARGET,
                      "The named target is not the eNB that received the message", CauseHoTargetNotAllowed);
    if (target.identity.tac == 0)
        return Refuse(AdmissionRefusal::UNSUPPORTED_TARGET, "The target cell is not available",
                      CauseCellNotAvailable);
    return std::nullopt;
}

} // namespace lte::enb::s1ap
