# Okta → AWS S3 with trusted identity propagation (minimal demo)

A user signs in to a small Python web app with **Okta**. The app then reads a file from
**S3** *as that Okta user*. AWS decides access based on who the person is, not on a shared
app role. S3 Access Grants gives each Identity Center user or group access to specific prefixes,
and CloudTrail records the real user.

```
 Browser ──login──▶ Okta (OIDC app)  ── ID token (iss = Okta, aud = Okta client ID)
                                          │
 app.py ──────────────────────────────────┘
   │ 1. sso-oidc:CreateTokenWithIAM      Identity Center: "trusted issuer? right aud?" → maps email → IdC user
   │ 2. sts:AssumeRole + ProvidedContexts  role session now carries the IdC user's identity
   │ 3. s3:GetDataAccess                  S3 Access Grants: "does this user have a grant?" → scoped temp creds
   │ 4. s3:GetObject                      read the file
   ▼
 S3 bucket
```

Okta is used in two separate ways:

| Okta app | Purpose |
|---|---|
| **AWS IAM Identity Center** (from the Okta Integration Network, SAML + SCIM) | **Provisioning.** Okta pushes users and groups into IAM Identity Center so they exist on the AWS side. |
| **OIDC Web App** (one you create) | **Authentication for this demo app.** Its client ID becomes the `aud` in the ID token. |

The Okta OIDC app and the Identity Center "customer managed application" are linked only by
two values you copy from Okta into AWS: the **issuer URL** and the **client ID (audience)**.
`setup_aws.py` sets both.

## Files

| File | What it does |
|---|---|
| `app.py` | Flask app: Okta login (auth code + PKCE) and a "fetch file" page that shows each hop |
| `tip.py` | The 4 AWS calls above, one function each |
| `setup_aws.py` | One-time AWS setup: IAM roles, trusted token issuer, Identity Center app, S3 Access Grants, demo bucket |
| `.env.example` | All configuration |

## Prerequisites

- An Okta org (a free Integrator/developer org works) where you're an admin.
- An AWS account with admin access and the AWS CLI credentials configured locally.
- Python 3.9+.

## Step 1: Provision Okta users into IAM Identity Center (SCIM)

1. In the AWS console, **enable IAM Identity Center** in your chosen region. Use that region for `AWS_REGION` everywhere.
2. In Okta, go to **Applications → Browse App Catalog → "AWS IAM Identity Center" → Add**.
3. Connect Okta as the identity source (AWS docs: *"Configure SAML and SCIM with Okta and IAM Identity Center"*):
   - IAM Identity Center → **Settings → Identity source → Change → External identity provider**. Exchange SAML metadata with the Okta app's **Sign On** tab.
   - IAM Identity Center → **Settings → Automatic provisioning → Enable**. Copy the **SCIM endpoint** and **access token** into the Okta app's **Provisioning → Integration** tab and turn on *Create / Update / Deactivate Users*.
4. **Assign** your demo user (e.g. `alice@example.com`) to that Okta app, and optionally a second user (`bob@…`) without a grant to show a denial.
5. Check that the user appears under IAM Identity Center → **Users** with the **same email** as in Okta.

> Shortcut for a quick test: skip SAML/SCIM and create the user manually in the Identity Center
> directory with the same email as the Okta user. The token exchange only needs the email to match.

## Step 2: Create the Okta OIDC app for the demo

1. Okta Admin → **Applications → Create App Integration → OIDC - OpenID Connect → Web Application**.
2. **Sign-in redirect URI:** `http://localhost:5000/callback`. **Sign-out redirect URI:** `http://localhost:5000`.
3. Grant type: **Authorization Code**. Assign it to the same users as in Step 1.
4. Copy the **Client ID** and **Client secret**.
5. Pick the issuer. With the default custom authorization server it is
   `https://<your-org>.okta.com/oauth2/default` (**Security → API → Authorization Servers**).
   Make sure that server's access policy allows this app. The "Default Policy" for "All clients" does.

## Step 3: Configure and run the AWS setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # fill in OKTA_*, AWS_REGION, S3_BUCKET, DEMO_USER_EMAIL
python setup_aws.py         # prints APP_ROLE_ARN and IDC_APPLICATION_ARN
```

Paste the two printed ARNs into `.env`. The script creates:

- **`OktaS3DemoAppRole`**: the role the app uses. Your local credentials assume it. It can call `CreateTokenWithIAM` and `GetDataAccess`, and its trust policy allows `sts:SetContext`.
- **Trusted token issuer**: the Okta issuer URL. Okta's `email` claim is matched to the Identity Center user's email.
- **Customer managed application `okta-s3-demo`**:
  - *Grant:* JWT bearer tokens from that issuer with `aud` = your Okta client ID
  - *Actor policy:* only `OktaS3DemoAppRole` may call `CreateTokenWithIAM` against it
  - *Scope:* `s3:access_grants:read_write`
- **S3 Access Grants**: an instance linked to Identity Center, a location for `s3://<bucket>/` (backed by `OktaS3DemoAccessGrantsLocationRole`), and **one grant: `DEMO_USER_EMAIL` → READ `demo/*`**.
- **Bucket** with `demo/hello.txt` (granted) and `private/secret.txt` (not granted).

## Step 4: Run the demo

```bash
python app.py
```

Open http://localhost:5000, then:

1. Sign in as **alice** and fetch `demo/hello.txt`. The file appears, with a trace showing the Okta
   claims, the Identity Center user, and the Access Grant that matched.
2. Fetch `private/secret.txt`. You get **AccessDenied from GetDataAccess**, because alice has no grant there.
3. Sign out and sign in as **bob**. `demo/hello.txt` is now denied too. Same app, same IAM role,
   different result, because access follows the Okta identity.
4. Optional: in **CloudTrail**, the `GetDataAccess` event includes `onBehalfOf` with the Identity Center user ID.

## Troubleshooting

| Error | Usual cause |
|---|---|
| `CreateTokenWithIAM` → `InvalidGrantException` | Issuer URL in `.env` ≠ `iss` in the token (check trailing slash and `/oauth2/default`), or client ID ≠ `aud`. |
| `CreateTokenWithIAM` → `AccessDeniedException` | The caller isn't `OktaS3DemoAppRole`, or the Okta user's email doesn't exist in Identity Center (check SCIM). |
| `AssumeRole` → `AccessDenied` | Your local credentials can't assume the role, or its trust policy is missing `sts:SetContext`. |
| `GetDataAccess` → `AccessDenied` | No grant covers the key for this user. This is the expected denial. |
| Region errors | Identity Center, Access Grants and `AWS_REGION` must all be in the same region. |

## Cleanup

In the AWS console: delete the access grant, location and Access Grants instance (S3 → Access Grants);
delete the `okta-s3-demo` application and `okta-s3-demo-issuer` trusted token issuer (IAM Identity Center);
delete both `OktaS3Demo*` IAM roles; empty and delete the bucket.

## Not production-ready

This is a demo. The app doesn't verify the Okta ID token signature itself (AWS verifies it in step 1),
stores tokens in Flask's cookie session, and runs Flask's dev server.
