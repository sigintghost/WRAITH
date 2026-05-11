# admin/ — operator control plane

Authentication, authorization, and key management.
Highest sensitivity directory in WRAITH.
Hash check auth.py and keys_manager.py on every launch.
If auth.py is tampered, all access controls fail.

admin.py       — admin menu functions
auth.py        — SHA256 auth, roles, UUID, lockout
keys_manager.py— API key management and validation
keys_template.py— key scaffold, never contains real keys

Keys live at ~/.wraith/keys.py — chmod 600 — never in repo.
Auth config at ~/.wraith/auth.cfg — chmod 600 — never in repo.
