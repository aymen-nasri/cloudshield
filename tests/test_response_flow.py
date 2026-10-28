"""The response workflow end to end, against both store backends (T-01, T-07, T-08 and friends)."""

from types import SimpleNamespace

import pytest

from cases.state import ProposalState
from common.models import Target
from core.auth import Principal
from correlation.engine import CorrelationEngine
from ingestion.evidence import InMemoryEvidenceStore
from ingestion.pipeline import IngestPipeline
from policy.engine import load_policies
from responder.executor import KubernetesExecutor
from responder.quarantine import QUARANTINE_LABEL
from response.records import AlreadyExecuted, Execution
from response.service import Conflict, Forbidden, Invalid, ResponseService
from tests.conftest import NOW, fixture_bytes
from tests.fakes import Clock, FakePodApi

POD = "checkout-7d9f6c-x2k8p"
POD_UID = "8b0e3c52-1d7a-4f43-9e6b-3a2c5d9f0e17"
TARGET = Target(kind="Pod", name=POD, uid=POD_UID, namespace="shop")

ALICE = Principal("analyst:alice", frozenset({"analyst"}))  # proposes
BOB = Principal("analyst:bob", frozenset({"incident-responder"}))  # approves and executes
CAROL = Principal("analyst:carol", frozenset({"incident-responder"}))
VIC = Principal("analyst:vic", frozenset({"viewer"}))

QUARANTINE = "k8s.pod.quarantine_label"
S = ProposalState


@pytest.fixture
def env(stores, falco, guardduty):
    engine = CorrelationEngine(stores.cases)
    pipeline = IngestPipeline(stores.events, InMemoryEvidenceStore(), on_accepted=engine.correlate)
    pipeline.ingest(fixture_bytes("s1_suspicious_process", "guardduty_finding.json"), guardduty)
    pipeline.ingest(fixture_bytes("s1_suspicious_process", "falco_alert.json"), falco)
    [case] = stores.cases.list()

    pods = FakePodApi(name=POD, uid=POD_UID)
    clock = Clock(NOW)
    service = ResponseService(
        stores.proposals,
        stores.cases,
        stores.audit,
        load_policies(),
        KubernetesExecutor(pods),
        environment="lab",
        clock=clock,
    )
    return SimpleNamespace(service=service, pods=pods, clock=clock, case_id=case.case_id, stores=stores)


def _ready(env, by=ALICE):
    """Create and dry-run a quarantine proposal; return it awaiting approval."""
    record = env.service.create(env.case_id, by, action_type=QUARANTINE, target=TARGET, rationale="curl | sh")
    return env.service.dry_run(record.proposal.proposal_id, BOB)


def _approve(env, record, who=BOB):
    return env.service.decide(
        record.proposal.proposal_id, who, decision="approve", bound_hash=record.proposal_hash,
        justification="confirmed remote script execution",
    )  # fmt: skip


def test_t01_happy_path_is_verified_and_audited(env):
    record = env.service.create(env.case_id, ALICE, action_type=QUARANTINE, target=TARGET, rationale="x")
    assert record.state is S.PROPOSED
    assert record.proposal.target.labels == {"app": "checkout"}  # from the live pod

    record = env.service.dry_run(record.proposal.proposal_id, BOB)
    assert record.state is S.AWAITING_APPROVAL
    assert record.proposal.dry_run_passed is True
    assert record.proposal.impact_preview["allow_policies_lost"] == ["checkout-allow"]
    assert env.pods.real_patches == []  # dry-run changed nothing

    record = _approve(env, record)
    assert record.state is S.APPROVED

    record = env.service.execute(record.proposal.proposal_id, BOB)
    assert record.state is S.VERIFIED
    assert env.pods.labels[QUARANTINE_LABEL] == "true"
    assert env.pods.real_patches == [{QUARANTINE_LABEL: "true"}]

    reloaded = env.service.get(record.proposal.proposal_id)
    assert reloaded.state is S.VERIFIED
    assert reloaded.execution.checks["no_allow_policy_selects_pod"] is True
    assert reloaded.execution.checks["egress_probe"] is None
    assert [a.approver for a in reloaded.approvals] == [BOB.id]

    actions = [r.action for r in env.stores.audit.records(env.case_id)]
    for expected in ("proposal.proposed", "proposal.awaiting_approval", "proposal.approved",
                     "proposal.executing", "proposal.verified"):  # fmt: skip
        assert expected in actions
    assert env.stores.audit.verify() is None


def test_viewers_cannot_propose(env):
    with pytest.raises(Forbidden):
        env.service.create(env.case_id, VIC, action_type=QUARANTINE, target=TARGET, rationale="x")


def test_target_must_belong_to_the_case(env):
    other = TARGET.model_copy(update={"name": "cart-5c8b7d-m4q2z"})
    with pytest.raises(Invalid, match="does not appear in case"):
        env.service.create(env.case_id, ALICE, action_type=QUARANTINE, target=other, rationale="x")


def test_target_uid_must_match_the_live_pod(env):
    stale = TARGET.model_copy(update={"uid": "someone-elses-pod"})
    with pytest.raises(Invalid, match="UID"):
        env.service.create(env.case_id, ALICE, action_type=QUARANTINE, target=stale, rationale="x")


def test_actions_without_an_executor_are_refused(env):
    with pytest.raises(Invalid, match="no executor"):
        env.service.create(env.case_id, ALICE, action_type="notify.slack", target=TARGET, rationale="x")


def test_requester_cannot_approve_their_own_proposal(env):
    record = _ready(env, by=BOB)
    with pytest.raises(Forbidden, match="own proposal"):
        _approve(env, record, who=BOB)


def test_role_is_required_to_approve(env):
    record = _ready(env)
    with pytest.raises(Forbidden, match="roles"):
        _approve(env, record, who=VIC)


def test_approval_for_a_different_version_is_refused(env):
    record = _ready(env)
    with pytest.raises(Conflict, match="proposal_hash"):
        env.service.decide(
            record.proposal.proposal_id, BOB, decision="approve", bound_hash="sha256:old", justification="ok"
        )
    assert env.service.get(record.proposal.proposal_id).state is S.AWAITING_APPROVAL


def test_each_approver_decides_once(env):
    critical = FakePodApi(
        name=POD, uid=POD_UID, labels={"app": "checkout", "cloudshield.io/tier": "critical"}
    )
    env.service.executor = KubernetesExecutor(critical)
    record = _ready(env)
    _approve(env, record)
    with pytest.raises(Conflict, match="already decided"):
        _approve(env, record)


def test_critical_targets_need_two_approvers(env):
    critical = FakePodApi(
        name=POD, uid=POD_UID, labels={"app": "checkout", "cloudshield.io/tier": "critical"}
    )
    env.service.executor = KubernetesExecutor(critical)
    record = _ready(env)
    assert record.policy.required_approvals == 2

    assert _approve(env, record, who=BOB).state is S.AWAITING_APPROVAL
    assert _approve(env, record, who=CAROL).state is S.APPROVED


def test_t07_rejection_stops_everything(env):
    record = _ready(env)
    record = env.service.decide(
        record.proposal.proposal_id, BOB, decision="reject", bound_hash=record.proposal_hash,
        justification="benign: scheduled maintenance",
    )  # fmt: skip
    assert record.state is S.REJECTED
    with pytest.raises(Conflict):
        env.service.execute(record.proposal.proposal_id, BOB)
    assert env.pods.real_patches == []


def test_t07_approval_that_expires_before_execution_runs_nothing(env):
    record = _approve(env, _ready(env))
    env.clock.advance(minutes=16)
    with pytest.raises(Conflict, match="approvals no longer valid"):
        env.service.execute(record.proposal.proposal_id, BOB)
    assert env.service.get(record.proposal.proposal_id).state is S.REJECTED
    assert env.pods.real_patches == []


def test_target_replaced_after_approval_runs_nothing(env):
    record = _approve(env, _ready(env))
    env.pods.pod["metadata"]["uid"] = "replacement-pod"  # same name, new pod
    with pytest.raises(Conflict, match="policy now denies"):
        env.service.execute(record.proposal.proposal_id, BOB)
    assert env.service.get(record.proposal.proposal_id).state is S.REJECTED
    assert env.pods.real_patches == []


def test_executes_at_most_once(env):
    record = _approve(env, _ready(env))
    env.service.execute(record.proposal.proposal_id, BOB)
    with pytest.raises(Conflict):
        env.service.execute(record.proposal.proposal_id, BOB)
    assert len(env.pods.real_patches) == 1


def test_store_refuses_a_second_execution_record(env):
    record = _approve(env, _ready(env))
    pid = record.proposal.proposal_id
    env.stores.proposals.start_execution(pid, Execution("exe_1", "responder", started_at=NOW))
    with pytest.raises(AlreadyExecuted):
        env.stores.proposals.start_execution(pid, Execution("exe_2", "responder", started_at=NOW))


def test_proposal_expires_if_left_too_long(env):
    record = env.service.create(env.case_id, ALICE, action_type=QUARANTINE, target=TARGET, rationale="x")
    env.clock.advance(hours=2)
    with pytest.raises(Conflict, match="expired"):
        env.service.dry_run(record.proposal.proposal_id, BOB)
    assert env.service.get(record.proposal.proposal_id).state is S.REJECTED


def test_t08_executor_failure_is_recorded_and_escalated(env):
    record = _approve(env, _ready(env))

    def broken(*args, **kwargs):
        raise TimeoutError("kubernetes API timed out")

    env.pods.patch_pod_labels = broken
    record = env.service.execute(record.proposal.proposal_id, BOB)
    assert record.state is S.FAILED
    assert record.execution.status == "error"
    assert any(r.action == "proposal.failed" for r in env.stores.audit.records(env.case_id))


def test_rollback_restores_normal_policies(env):
    env.service.execute(_approve(env, _ready(env)).proposal.proposal_id, BOB)

    rollback = env.service.create(
        env.case_id, ALICE, action_type="k8s.pod.remove_quarantine_label", target=TARGET, rationale="benign"
    )
    rollback = _approve(env, env.service.dry_run(rollback.proposal.proposal_id, BOB))
    done = env.service.execute(rollback.proposal.proposal_id, BOB)

    assert done.state is S.VERIFIED
    assert QUARANTINE_LABEL not in env.pods.labels
    assert done.execution.checks == {"label_removed": True, "allow_policies_apply_again": True}
    assert len(env.service.list_for_case(env.case_id)) == 2
