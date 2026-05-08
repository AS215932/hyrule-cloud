with open("/home/svag/Dev/hyrule-cloud/hyrule_cloud/db.py", "r") as f:
    text = f.read()

import re
text = re.sub(r'class AccountRow.*?server_default=func.now\(\)\)\n', '', text, flags=re.DOTALL)
text = text.replace('import secrets\nimport string\n\ndef generate_account_id():\n    return \'\'.join(secrets.choice(string.ascii_uppercase) for _ in range(10))\n', '')

account_code = """
import secrets
import string

def generate_account_id():
    return ''.join(secrets.choice(string.ascii_uppercase) for _ in range(10))

class AccountRow(Base):
    __tablename__ = "accounts"
    account_id: Mapped[str] = mapped_column(String(10), primary_key=True, default=generate_account_id)
    api_key: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
"""

text = text + "\n" + account_code

with open("/home/svag/Dev/hyrule-cloud/hyrule_cloud/db.py", "w") as f:
    f.write(text)

