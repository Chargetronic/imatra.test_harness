"""Checks every exchange of the harness against the Imatra contracts.

The contracts are the AsyncAPI documents in ``contracts/``. A message is
matched to a channel by its topic and validated against the channel's
message payload schema; a few rules the schemas cannot express (exactly one
of a result and an error) are checked on top.
"""

from .spec import Contracts, Problem, load

__all__ = ["Contracts", "Problem", "load"]
