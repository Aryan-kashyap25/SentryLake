"""
generate_mock_data.py — SentryLake Mock Data Generator
Generates a 100-row realistic banking CSV with embedded PII,
null spikes, type mismatches, and outliers for testing.
"""

import csv
import random
import numpy as np
from datetime import datetime, timedelta

random.seed(42)
np.random.seed(42)

# ── Reference Data ──────────────────────────────────────────────────────────

FIRST_NAMES = [
    "James", "Mary", "Robert", "Patricia", "John", "Jennifer", "Michael",
    "Linda", "David", "Elizabeth", "William", "Barbara", "Richard", "Susan",
    "Joseph", "Jessica", "Thomas", "Sarah", "Christopher", "Karen",
    "Charles", "Lisa", "Daniel", "Nancy", "Matthew", "Betty", "Anthony",
    "Margaret", "Mark", "Sandra",
]

LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
    "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez",
    "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin",
    "Lee", "Perez", "Thompson", "White", "Harris", "Sanchez", "Clark",
    "Ramirez", "Lewis", "Robinson",
]

MAIDEN_NAMES = [
    "O'Brien", "Sullivan", "Murphy", "Kelly", "Walsh", "Kennedy",
    "Brennan", "Gallagher", "Doyle", "Flynn", "McCarthy", "Quinn",
    "Burke", "Byrne", "Fitzgerald", "Connolly", "Daly", "Powers",
    "Nolan", "Reilly",
]

EMAIL_DOMAINS = ["gmail.com", "yahoo.com", "bankmail.com", "outlook.com", "corpfin.net"]

AREA_CODES = ["212", "312", "713", "602", "415", "305", "214", "404", "206", "303"]

ACCOUNT_TYPES = ["Checking", "Savings", "Investment", "Credit"]

BRANCH_CITIES = [
    "New York", "Chicago", "Houston", "Phoenix", "Los Angeles",
    "Philadelphia", "San Antonio", "Dallas", "San Jose", "Austin",
    "Miami", "Seattle", "Denver", "Atlanta", "Boston",
]

NORMAL_NOTES = [
    "Monthly payment", "Wire transfer", "ATM withdrawal",
    "Direct deposit", "Payroll credit", "Mortgage payment",
    "Insurance premium", "Utility bill payment", "Recurring subscription",
    "Investment dividend", "Loan repayment", "Refund processed",
    "Cash deposit", "Inter-account transfer", "Service charge",
    "Interest payment", "Online purchase", "Mobile deposit",
    "Foreign exchange", "Account maintenance fee",
]

CC_PREFIXES = ["4532", "4916", "5274", "5425", "3782", "4012", "5105", "4111"]

# ── Helper Functions ────────────────────────────────────────────────────────

def generate_cc_number() -> str:
    """Generate a realistic 16-digit credit card number with dashes."""
    prefix = random.choice(CC_PREFIXES)
    remaining = "".join([str(random.randint(0, 9)) for _ in range(12)])
    number = prefix + remaining
    return f"{number[0:4]}-{number[4:8]}-{number[8:12]}-{number[12:16]}"


def generate_ssn() -> str:
    """Generate a realistic SSN in AAA-GG-SSSS format."""
    area = random.randint(100, 899)
    group = random.randint(10, 99)
    serial = random.randint(1000, 9999)
    return f"{area}-{group}-{serial}"


def generate_phone() -> str:
    """Generate a US phone number in (XXX) XXX-XXXX format."""
    area = random.choice(AREA_CODES)
    mid = random.randint(200, 999)
    last = random.randint(1000, 9999)
    return f"({area}) {mid}-{last}"


def generate_ip() -> str:
    """Generate an IPv4 address."""
    octets = [
        random.choice([10, 172, 192]),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(1, 254),
    ]
    return ".".join(map(str, octets))


def generate_email(first: str, last: str) -> str:
    """Generate a realistic email from a name."""
    domain = random.choice(EMAIL_DOMAINS)
    style = random.choice([
        f"{first.lower()}.{last.lower()}",
        f"{first[0].lower()}.{last.lower()}",
        f"{first.lower()}{random.randint(1, 99)}",
        f"{first.lower()}_{last.lower()}",
    ])
    return f"{style}@{domain}"


def generate_pii_note() -> str:
    """Generate a note containing embedded PII."""
    templates = [
        f"Call me at {random.choice(AREA_CODES)}-{random.randint(200,999)}-{random.randint(1000,9999)}",
        f"Email backup: {random.choice(FIRST_NAMES).lower()}@email.com",
        f"Card ending {generate_cc_number()}",
        f"Alternate contact: {random.choice(AREA_CODES)}-{random.randint(200,999)}-{random.randint(1000,9999)}",
        f"Send receipt to {random.choice(FIRST_NAMES).lower()}.{random.choice(LAST_NAMES).lower()}@gmail.com",
    ]
    return random.choice(templates)


# ── Main Generation ─────────────────────────────────────────────────────────

def generate_dataset(num_rows: int = 100) -> list[dict]:
    """Generate the complete banking dataset."""
    base_date = datetime(2024, 1, 1)
    rows = []

    # Pre-determine which rows get null emails (~18%)
    null_email_indices = set(random.sample(range(num_rows), k=int(num_rows * 0.18)))

    # Pre-determine type mismatch rows for transaction_amount (~5%)
    type_mismatch_indices = set(random.sample(range(num_rows), k=int(num_rows * 0.05)))
    noise_values = ["N/A", "pending", "ERROR", "#REF!", "null"]

    # Pre-determine outlier rows (5 extreme values)
    outlier_indices = set(random.sample(
        [i for i in range(num_rows) if i not in type_mismatch_indices], k=5
    ))

    for i in range(num_rows):
        first = random.choice(FIRST_NAMES)
        last = random.choice(LAST_NAMES)

        # Transaction amount with outliers and type noise
        if i in type_mismatch_indices:
            amount = random.choice(noise_values)
        elif i in outlier_indices:
            amount = round(random.uniform(50000, 99999.99), 2)
        else:
            amount = round(random.uniform(10.0, 5000.0), 2)

        row = {
            "transaction_id": f"TXN-{i + 1:06d}",
            "customer_name": f"{first} {last}",
            "email": "" if i in null_email_indices else generate_email(first, last),
            "phone_number": generate_phone(),
            "ssn": generate_ssn() if random.random() < 0.40 else "",
            "credit_card_number": generate_cc_number() if random.random() < 0.60 else "",
            "ip_address": generate_ip() if random.random() < 0.70 else "",
            "transaction_amount": amount,
            "transaction_date": (base_date + timedelta(days=random.randint(0, 364))).strftime("%Y-%m-%d"),
            "account_type": random.choice(ACCOUNT_TYPES),
            "branch_location": random.choice(BRANCH_CITIES),
            "mother_maiden_name": random.choice(MAIDEN_NAMES) if random.random() < 0.50 else "",
            "notes": generate_pii_note() if random.random() < 0.20 else random.choice(NORMAL_NOTES),
        }
        rows.append(row)

    return rows


def main():
    """Generate and save the mock dataset."""
    print("=" * 65)
    print("  SENTRYLAKE — Mock Data Generator")
    print("=" * 65)

    rows = generate_dataset(100)
    output_file = "customer_transactions_dirty.csv"

    fieldnames = list(rows[0].keys())
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    # Summary
    print(f"\n[OK] Generated {len(rows)} rows -> {output_file}")
    print(f"  Columns: {len(fieldnames)}")
    for col in fieldnames:
        non_empty = sum(1 for r in rows if r[col] not in ("", None))
        pct = (non_empty / len(rows)) * 100
        print(f"    • {col:<25s}  {non_empty:>3d}/100  ({pct:.0f}% populated)")

    # Count embedded PII in notes
    pii_notes = sum(1 for r in rows if any(k in str(r["notes"]) for k in ["@", "Card ending", "Call me at"]))
    type_noise = sum(1 for r in rows if isinstance(r["transaction_amount"], str))
    print(f"\n  Embedded PII in notes:     {pii_notes}")
    print(f"  Type mismatches in amount: {type_noise}")
    print(f"  Null emails:               {sum(1 for r in rows if r['email'] == '')}")
    print(f"\n{'=' * 65}")
    print("  Ready for SentryLake pipeline ingestion.")
    print("=" * 65)


if __name__ == "__main__":
    main()
