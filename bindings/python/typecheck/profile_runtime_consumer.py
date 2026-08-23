from typing import NoReturn

from auths.profile_runtime import Completed, ProfileOutcome


def completed_value(outcome: ProfileOutcome[int, NoReturn, NoReturn]) -> int:
    if isinstance(outcome, Completed):
        return outcome.value
    return 0
