import math
import secrets
import string
from dataclasses import dataclass


SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"
SYMBOLS_SET = set(SYMBOLS)
GUESSES_PER_SECOND = 1e10  # 10 billion guesses per second


def generate_password(
    length: int = 20,
    use_lower: bool = True,
    use_upper: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
) -> str:
    """
    Generate a random password with the requested length and character sets.

    Guarantees that if a character set is enabled, the password will include at
    least one character from that set (assuming length is sufficient).
    """
    pools = []

    if use_lower:
        pools.append(string.ascii_lowercase)
    if use_upper:
        pools.append(string.ascii_uppercase)
    if use_digits:
        pools.append(string.digits)
    if use_symbols:
        pools.append(SYMBOLS)

    if not pools:
        raise ValueError("At least one character set must be selected.")

    if length < len(pools):
        raise ValueError(
            "Password length must be at least the number of selected character "
            f"sets ({len(pools)})."
        )

    password_chars = [secrets.choice(pool) for pool in pools]
    alphabet = "".join(pools)

    remaining = length - len(password_chars)
    password_chars.extend(secrets.choice(alphabet) for _ in range(remaining))

    rng = secrets.SystemRandom()
    rng.shuffle(password_chars)

    return "".join(password_chars)


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


def _plural(value: float, unit: str) -> str:
    # Small fix: use singular when exactly 1.0
    return unit if abs(value - 1.0) < 1e-9 else unit + "s"


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
        s = round(seconds, 1)
        return f"{s:.1f} {_plural(s, 'second')}"
    if seconds < hour:
        m = round(seconds / minute, 1)
        return f"{m:.1f} {_plural(m, 'minute')}"
    if seconds < day:
        h = round(seconds / hour, 1)
        return f"{h:.1f} {_plural(h, 'hour')}"
    if seconds < year:
        d = round(seconds / day, 1)
        return f"{d:.1f} {_plural(d, 'day')}"

    years = seconds / year
    if years < 1_000:
        y = round(years, 1)
        return f"{y:.1f} {_plural(y, 'year')}"
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
    has_symbol = any(c in SYMBOLS_SET for c in password)

    alphabet_size = (
        (26 if has_lower else 0)
        + (26 if has_upper else 0)
        + (10 if has_digit else 0)
        + (len(SYMBOLS) if has_symbol else 0)
    )

    bits = estimate_entropy_bits(length, alphabet_size)
    seconds = estimate_crack_time_seconds(bits)
    return PasswordAnalysis(password, length, alphabet_size, bits, seconds)
