🕵️‍♂️ Secret Discovery / Secrets Hunting:

🎯 Targets:
- AWS Keys, RSA Private Keys, Google API Keys, Twilio Tokens, JWT Secrets, DB Credentials (Mongo/MySQL)

🧰 Tools:
1. Extension/Web: Trufflehog
2. Static Analysis: gitleaks, gf secrets, shhgit
3. Dynamic Analysis: SecretFinder, nuclei + templates
   
(GitRob - detect-secrets)

link:
  1. https://chromewebstore.google.com/detail/trufflehog/bafhdnhjnlcdbjcdcnafhdcphhnfnhjc
  2. https://github.com/gitleaks/gitleaks
  3. https://github.com/m4ll0k/SecretFinder

AWS:
Enumerate IAM permissions:

enumerate-iam (- ./enumerate-iam.py --access-key AKIA... --secret-key StF0q... -)
---
API



