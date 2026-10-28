"""Run one investigation: render evidence, call the model, validate, record what happened."""

from dataclasses import dataclass
from importlib import resources
from typing import Protocol

from common.models import Investigation
from investigator.bundle import EvidenceBundle, render_untrusted
from investigator.validate import InvestigationRejected, parse_and_validate

PROMPT_VERSION = "investigate_v1"


class LanguageModel(Protocol):
    model_id: str

    def complete(self, system: str, user: str, *, max_tokens: int = 2000) -> str: ...


@dataclass(frozen=True)
class InvestigationRun:
    investigation: Investigation
    model_id: str
    prompt_version: str
    attempts: int


def load_prompt(version: str = PROMPT_VERSION) -> str:
    return resources.files("investigator").joinpath(f"prompts/{version}.md").read_text(encoding="utf-8")


class Investigator:
    def __init__(self, model: LanguageModel, *, max_attempts: int = 2) -> None:
        self.model = model
        self.max_attempts = max_attempts
        self.system_prompt = load_prompt()

    def investigate(self, bundle: EvidenceBundle, question: str | None = None) -> InvestigationRun:
        task = question or "Investigate this case and return the JSON object described in your rules."
        user = f"{render_untrusted(bundle)}\n\nTask: {task}"
        problems: list[str] = []

        for attempt in range(1, self.max_attempts + 1):
            prompt = user
            if problems:
                # Feed back only our own validator messages, never evidence text.
                prompt += "\n\nYour previous answer was rejected:\n- " + "\n- ".join(problems)
            text = self.model.complete(self.system_prompt, prompt)
            try:
                inv = parse_and_validate(text, bundle)
            except InvestigationRejected as exc:
                problems = exc.problems
                continue
            return InvestigationRun(inv, self.model.model_id, PROMPT_VERSION, attempt)

        raise InvestigationRejected(problems)
