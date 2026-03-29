"""
Chharcop intake module.

Ingests scam reports from multiple channels:
- Email (via IMAP / ProtonMail Bridge): :mod:`~chharcop.intake.email_intake`
- SMS / voicemail forwarding:           :mod:`~chharcop.intake.phone_intake`
"""

from chharcop.intake.email_intake import EmailIntake, InvestigationCase
from chharcop.intake.phone_intake import PhoneIntake, PhoneCase

__all__ = ["EmailIntake", "InvestigationCase", "PhoneIntake", "PhoneCase"]
