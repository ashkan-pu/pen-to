🕵️‍♂️ Secret Discovery OR Secrets Hunting:

AWS:

Found AWS API Keys:

  1. EXTENTION-WEB:    Trufflehog
  2. static-Analysis:  gitleaks(- gitleaks --repo-url=https:// -v -)
  3. Dynamic-Analysis: SecretFinder (- cat ../urll.txt | while read url ; do python SecretFinder.py -i $url -o cli ; done -)
link:
  1. https://chromewebstore.google.com/detail/trufflehog/bafhdnhjnlcdbjcdcnafhdcphhnfnhjc
  2. https://github.com/gitleaks/gitleaks
  3. https://github.com/m4ll0k/SecretFinder

Enumerate IAM permissions:
enumerate-iam (- ./enumerate-iam.py --access-key AKIA... --secret-key StF0q... -)


