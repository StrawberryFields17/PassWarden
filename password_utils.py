import math
import secrets
import string
from dataclasses import dataclass


SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"
GUESSES_PER_SECOND = 1e10  # 10 billion guesses per second


def generate_password(
    length: int = 20,
    use_lower: bool = True,
    use_upper: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
) -> str:
    if not any([use_lower, use_upper, use_digits, use_symbols]):
        raise ValueError("At least one character set must be selected.")

    alphabet = ""
    if use_lower:
        alphabet += string.ascii_lowercase
    if use_upper:
        alphabet += string.ascii_uppercase
    if use_digits:
        alphabet += string.digits
    if use_symbols:
        alphabet += SYMBOLS

    return "".join(secrets.choice(alphabet) for _ in range(length))


def estimate_entropy_bits(length: int, alphabet_size: int) -> float:
    if length <= 0 or alphabet_size <= 1:
        return 0.0
    return length * math.log2(alphabet_size)


def classify_strength(bits: float) -> str:
    if bits < 40:
        return "Weak"
    elif bits < 60:
        return "Okay"
    elif bits < 90:
        return "Strong"
    else:
        return "Very strong"


def estimate_crack_time_seconds(bits: float, guesses_per_second: float = GUESSES_PER_SECOND) -> float:
    if bits <= 0 or guesses_per_second <= 0:
        return 0.0
    return math.pow(2.0, bits - 1.0) / guesses_per_second


def format_duration(seconds: float) -> str:
    if seconds <= 0:
        return "instant"
    if seconds < 1:
        return "< 1 second"

    minute = 60
    hour = 60 * minute
    day = 24 * hour
    year = 365.25 * day

    if seconds < minute:
        return f"{seconds:.1f} seconds"
    if seconds < hour:
        return f"{seconds / minute:.1f} minutes"
    if seconds < day:
        return f"{seconds / hour:.1f} hours"
    if seconds < year:
        return f"{seconds / day:.1f} days"

    years = seconds / year
    if years < 1_000:
        return f"{years:.1f} years"
    if years < 1_000_000:
        return f"~{years:,.0f} years"

    power = math.floor(math.log10(years))
    return f"> 10^{power} years"


@dataclass
class PasswordAnalysis:
    password: str
    length: int
    alphabet_size: int
    bits: float
    crack_seconds: float

    @property
    def strength_label(self) -> str:
        return classify_strength(self.bits)

    @property
    def crack_duration_text(self) -> str:
        return format_duration(self.crack_seconds)


def analyze_arbitrary_password(password: str) -> PasswordAnalysis:
    length = len(password)
    if length == 0:
        return PasswordAnalysis(password, 0, 0, 0.0, 0.0)

    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in SYMBOLS for c in password)

    alphabet_size = (
        (26 if has_lower else 0)
        + (26 if has_upper else 0)
        + (10 if has_digit else 0)
        + (len(SYMBOLS) if has_symbol else 0)
    )

    bits = estimate_entropy_bits(length, alphabet_size)
    seconds = estimate_crack_time_seconds(bits)
    return PasswordAnalysis(password, length, alphabet_size, bits, seconds)
