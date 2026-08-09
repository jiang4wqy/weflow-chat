from dataclasses import dataclass

from weflow_chat.validator.contracts import FingerprintSet


@dataclass(frozen=True, slots=True)
class AcceptanceRecord:
    uiConfirmed: bool
    validation: FingerprintSet | None
    active: FingerprintSet | None
