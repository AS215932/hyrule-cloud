with open("/home/svag/Dev/hyrule-cloud/hyrule_cloud/db.py", "r") as f:
    lines = f.readlines()

new_lines = []
for line in lines:
    new_lines.append(line)
    if "from __future__ import annotations" in line:
        new_lines.append("""
import secrets
import string

def generate_account_id():
    return ''.join(secrets.choice(string.ascii_uppercase) for _ in range(10))

class AccountRow(Base):
    __tablename__ = "accounts"
    account_id: Mapped[str] = mapped_column(String(10), primary_key=True, default=generate_account_id)
    api_key: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
""")

# remove the first instance of imports that caused the error (I'll just remove lines before futures)
for i, l in enumerate(new_lines):
    if "from __future__ import annotations" in l:
        new_lines = new_lines[i:]
        break

with open("/home/svag/Dev/hyrule-cloud/hyrule_cloud/db.py", "w") as f:
    f.writelines(new_lines)
