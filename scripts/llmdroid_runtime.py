"""Deterministic view matching and conservative paired-outcome classification.

This module has no Android or LLM dependency. Device execution adapters can
use it to decide whether a recorded action still has a unique target and to
compare results after the same logical action in both environments.
"""

from dataclasses import dataclass
from copy import deepcopy
import re


class SynchronizationError(ValueError):
    """The recorded action cannot be mapped to one unambiguous current target."""


@dataclass(frozen=True)
class ViewMatch:
    view: dict
    method: str


def needs_initial_app_launch(first_event_type):
    """Start the app only when the trace begins with an in-app action.

    Launching before a kill/start prefix changes first-run application state
    and can make onboarding controls disappear before the recorded launch.
    """
    return first_event_type not in {"intent", "kill_app"}


def match_view(recorded, current_views):
    """Require one exact view or one unambiguous identifier/text match.

    Coordinates alone are intentionally not used to match a recorded view;
    they can silently click a different control after a UI change.
    """
    if not isinstance(recorded, dict):
        raise SynchronizationError("recorded target view missing")
    views = [item for item in current_views if isinstance(item, dict)]
    view_str = recorded.get("view_str")
    if view_str:
        exact = [item for item in views if item.get("view_str") == view_str]
        if len(exact) == 1:
            return ViewMatch(exact[0], "view_str")
        if len(exact) > 1:
            raise SynchronizationError("multiple current views have the recorded view_str")

    resource_id = recorded.get("resource_id")
    class_name = recorded.get("class")
    if resource_id and class_name:
        candidates = [item for item in views
                      if item.get("resource_id") == resource_id and
                      item.get("class") == class_name]
        method = "resource_id_and_class"
    elif class_name and (recorded.get("text") or recorded.get("content_description")):
        candidates = [item for item in views if item.get("class") == class_name]
        method = "class_and_text"
    else:
        raise SynchronizationError("recorded target has no stable identifier")

    for key in ("text", "content_description"):
        value = recorded.get(key)
        if value and len(candidates) > 1:
            narrowed = [item for item in candidates if item.get(key) == value]
            if narrowed:
                candidates = narrowed
                method += f"_{key}"
    if len(candidates) != 1:
        raise SynchronizationError(
            "recorded target absent" if not candidates else "recorded target ambiguous")
    return ViewMatch(candidates[0], method)


def retarget_event(recorded_event, current_views, package_name):
    """Return a safe LLMDroid event payload for the current UI.

    Reject actions whose recorded coordinates would be the only way to infer
    intent.  Intent commands are restricted to this test application's launch
    and force-stop operations.
    """
    if not isinstance(recorded_event, dict):
        raise SynchronizationError("event payload missing")
    kind = recorded_event.get("event_type")
    if kind == "kill_app":
        stop_intent = recorded_event.get("stop_intent")
        if stop_intent != f"am force-stop {package_name}":
            raise SynchronizationError("unsupported or foreign kill-app command")
        # Upstream records KillAppEvent but cannot reconstruct it via
        # InputEvent.from_dict. Its supported IntentEvent has the same action.
        return {"event_type": "intent", "intent": stop_intent}, {"normalized_from": "kill_app"}
    if kind == "key":
        name = recorded_event.get("name")
        if name not in {"BACK", "MENU", "HOME"}:
            raise SynchronizationError("unsupported key event")
        return {"event_type": kind, "name": name}, {}
    if kind == "intent":
        intent = recorded_event.get("intent")
        allowed_start = (isinstance(intent, str) and re.fullmatch(
            rf"am start (?:-n )?{re.escape(package_name)}/[A-Za-z0-9_.$]+", intent))
        if not isinstance(intent, str) or not (
            intent == f"am force-stop {package_name}" or
            intent == f"am start {package_name}" or allowed_start
        ):
            raise SynchronizationError("unsupported or foreign intent")
        return {"event_type": kind, "intent": intent}, {}
    if kind in {"touch", "long_touch", "select", "unselect", "scroll", "set_text"}:
        match = match_view(recorded_event.get("view"), current_views)
        result = {"event_type": kind, "view": deepcopy(match.view), "x": None, "y": None}
        if kind == "long_touch":
            duration = recorded_event.get("duration", 2000)
            if not isinstance(duration, (int, float)) or not 1 <= duration <= 10000:
                raise SynchronizationError("invalid long-touch duration")
            result["duration"] = duration
        elif kind == "scroll":
            direction = recorded_event.get("direction")
            if not isinstance(direction, str) or direction.upper() not in {"UP", "DOWN", "LEFT", "RIGHT"}:
                raise SynchronizationError("invalid scroll direction")
            result["direction"] = direction.upper()
        elif kind == "set_text":
            value = recorded_event.get("text")
            if not isinstance(value, str) or len(value) > 256:
                raise SynchronizationError("invalid text action")
            result["text"] = value
        return result, {"view": match.method}
    if kind == "swipe":
        start = match_view(recorded_event.get("start_view"), current_views)
        end = match_view(recorded_event.get("end_view"), current_views)
        duration = recorded_event.get("duration", 1000)
        if not isinstance(duration, (int, float)) or not 1 <= duration <= 10000:
            raise SynchronizationError("invalid swipe duration")
        return {
            "event_type": kind, "start_view": deepcopy(start.view),
            "end_view": deepcopy(end.view), "start_x": None, "start_y": None,
            "end_x": None, "end_y": None, "duration": duration,
        }, {"start_view": start.method, "end_view": end.method}
    raise SynchronizationError("unsupported event type")


def compare_step(baseline, mutant):
    """Classify the first concrete difference at one synchronized action."""
    if baseline.get("index") != mutant.get("index"):
        return "synchronization_failure"
    statuses = {baseline.get("status"), mutant.get("status")}
    if statuses & {"infrastructure_error", "sync_failure", "unverified"}:
        return "inconclusive"
    if "crash" in statuses and statuses != {"crash"}:
        return "crash_candidate"
    if "anr" in statuses and statuses != {"anr"}:
        return "anr_candidate"
    if "timeout" in statuses and statuses != {"timeout"}:
        return "timeout_candidate"
    if baseline.get("status") != mutant.get("status"):
        return "action_outcome_divergence"
    if baseline.get("activity") != mutant.get("activity"):
        return "activity_divergence"
    if baseline.get("ui_structure") != mutant.get("ui_structure"):
        return "ui_divergence"
    return None


def first_divergence(baseline_steps, mutant_steps):
    if len(baseline_steps) != len(mutant_steps):
        # Compare available synchronized prefixes first; missing actions are
        # an execution failure, not automatically an app behavior change.
        common = min(len(baseline_steps), len(mutant_steps))
    else:
        common = len(baseline_steps)
    for index in range(common):
        kind = compare_step(baseline_steps[index], mutant_steps[index])
        if kind:
            return {"index": index, "classification": kind,
                    "baseline": baseline_steps[index], "mutant": mutant_steps[index]}
    if len(baseline_steps) != len(mutant_steps):
        return {"index": common, "classification": "inconclusive_missing_actions",
                "baseline_count": len(baseline_steps), "mutant_count": len(mutant_steps)}
    return None
