"""CVSS v3.1 base score calculator.

New in V2. Takes the six required base metrics and returns a vector + score.
Reference: https://www.first.org/cvss/v3.1/specification-document
"""

from __future__ import annotations

from dataclasses import dataclass


# --- Metric enum values (V3.1) ---------------------------------------------

# Attack Vector (AV): N=Network 0.85, A=Adjacent 0.62, L=Local 0.55, P=Physical 0.2
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}  # unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}    # changed
_UI = {"N": 0.85, "R": 0.62}
_C = {"H": 0.56, "L": 0.22, "N": 0.0}
_I = {"H": 0.56, "L": 0.22, "N": 0.0}
_A = {"H": 0.56, "L": 0.22, "N": 0.0}


@dataclass(frozen=True)
class CvssVector:
    AV: str = "N"
    AC: str = "L"
    PR: str = "N"
    UI: str = "N"
    C: str = "N"
    I: str = "N"
    A: str = "N"

    def to_string(self) -> str:
        return (f"CVSS:3.1/AV:{self.AV}/AC:{self.AC}/PR:{self.PR}/UI:{self.UI}"
                f"/C:{self.C}/I:{self.I}/A:{self.A}")


def score(vector: CvssVector) -> float:
    """Compute the CVSS v3.1 base score (0.0 - 10.0)."""
    iss = 1 - ((1 - _C[vector.C]) * (1 - _I[vector.I]) * (1 - _A[vector.A]))
    if iss <= 0:
        return 0.0

    if vector.C in ("H", "L") or vector.I in ("H", "L") or vector.A in ("H", "L"):
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss * 0.9731 - 0.02) ** 13)
    else:
        impact = 6.42 * iss

    exploitability = (
        8.22 * _AV[vector.AV] * _AC[vector.AC]
        * _PR_U[vector.PR] * _UI[vector.UI]
    )
    if impact <= 0:
        return 0.0
    if impact + exploitability <= 10.0:
        raw = round_up(impact + exploitability, 1)
    else:
        raw = 10.0
    return raw


def round_up(value: float, decimals: int = 1) -> float:
    """Round half-up to `decimals` places (CVSS spec requires this)."""
    multiplier = 10 ** decimals
    from math import floor
    return floor(value * multiplier + 0.5) / multiplier
