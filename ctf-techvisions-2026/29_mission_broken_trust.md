## 29 — Mission: Broken Trust (Cloud)

1. Open the challenge application and follow its role-handoff flow. The first stage gives a temporary handoff token or role credentials.
2. Enumerate IAM and Lambda from that identity. One Lambda function trusts a role that the current identity can reach. Invoke it to obtain the next role’s credentials.
3. Inspect the next role’s trust policy. A public or over-broad `sts:AssumeRole` statement allows the next hop.
4. Assume the role and read the secret named by the application.
5. Use the role session credentials to reach the final stage, then decrypt the supplied KMS ciphertext with the permitted key.
6. The six stage labels are reflected in the flag: role handoff, Lambda trust, public policy, secret read, role session, KMS decrypt.

`TVX{ROLE_HANDOFF_LAMBDA_TRUST_PUBLIC_POLICY_SECRET_READ_ROLE_SESSION_KMS_DECRYPT}`
