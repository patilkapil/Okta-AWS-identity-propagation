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

## How the two app registrations fit together

Nothing federates or syncs between the Okta app and AWS, but you register the app twice, once on
each side. A single value links the two registrations.

**In Okta (your IdP)**, the app is an OIDC client. When a user logs in, Okta issues a JWT whose
`aud` (audience) claim is that client's ID.

**In IAM Identity Center**, a separate *customer managed application* represents the same app on the
AWS side. You configure it with two things:

- **which trusted token issuer to accept tokens from:** Okta's issuer URL
- **which `aud` value to accept:** the Okta client ID

That `aud` value is the entire link. There's no handshake, redirect, or protocol connection between
the two apps. The Identity Center application just says: *"I'll accept JWTs signed by this issuer,
meant for this audience."* When the app calls `CreateTokenWithIAM`, it names this Identity Center
application, and Identity Center checks the incoming JWT against those rules.

**One more piece of wiring:** the app's IAM role needs permission to call the token exchange
(`sso-oauth:CreateTokenWithIAM`) against *that specific* Identity Center application. Otherwise any
role could present JWTs to it.

So the Okta app authenticates the user, and the Identity Center app decides whether to trust that
authentication. The two only know about each other through the issuer URL and audience you copy
from Okta into AWS.

## Files

| File | What it does |
|---|---|
| `app.py` | Flask app: Okta login (auth code + PKCE) and a "fetch file" page that shows each hop |
| `tip.py` | The 4 AWS calls above, one function each |
| `setup_aws.py` | One-time AWS setup: IAM roles, Identity Center customer managed application, S3 Access Grants, demo bucket |
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

## Step 3: Create a trusted token issuer in IAM Identity Center

`setup_aws.py` requires a trusted token issuer (TTI) to already exist — it reads its ARN from `TTI_ARN` in `.env` rather than creating one, so that re-runs don't touch this sensitive config.

1. In the AWS console, go to **IAM Identity Center → Settings → Trusted token issuers → Create**.
2. **Issuer URL:** your Okta issuer (e.g. `https://<your-org>.okta.com/oauth2/default`).
3. **Claim attribute path:** `email`. **Identity store attribute path:** `emails.value`. **JWKS retrieval:** `OPEN_ID_DISCOVERY`.
4. Copy the **Trusted token issuer ARN** — you'll put it in `TTI_ARN` in the next step.

## Step 4: Configure and run the AWS setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # fill in OKTA_*, AWS credentials, AWS_REGION, S3_BUCKET,
                            # DEMO_USER_EMAIL, INSTANCE_ARN, IDENTITY_STORE_ID, TTI_ARN
python setup_aws.py         # prints APP_ROLE_ARN and IDC_APPLICATION_ARN
```

`INSTANCE_ARN` and `IDENTITY_STORE_ID` are on the **IAM Identity Center → Settings** page.
`TTI_ARN` is the ARN you copied in Step 3.

Paste the two printed ARNs (`APP_ROLE_ARN`, `IDC_APPLICATION_ARN`) into `.env`.

Setup checklist. These are the pieces that must be in place, following
[How the two app registrations fit together](#how-the-two-app-registrations-fit-together):

1. **Okta OIDC client** (Step 2): note the **issuer URL** and **client ID**.
2. **Trusted token issuer** in IAM Identity Center (Step 3): points at the Okta **issuer URL**.
3. **Customer managed application** in IAM Identity Center: accepts JWTs from that trusted token
   issuer whose `aud` equals the Okta **client ID**.
4. **IAM role for the app**: allowed to call `sso-oauth:CreateTokenWithIAM` on that specific
   application, and named in the application's actor policy.
5. **S3 Access Grants**: grant the Identity Center user or group access to an S3 prefix.

The script creates:

- **`OktaS3DemoAppRole`**: the role the app uses. Your local credentials assume it. It can call `CreateTokenWithIAM` (only against the `okta-s3-demo` application) and `GetDataAccess`, and its trust policy allows `sts:SetContext`.
- **Customer managed application `okta-s3-demo`**:
  - *Grant:* JWT bearer tokens from that issuer with `aud` = your Okta client ID
  - *Actor policy:* only `OktaS3DemoAppRole` may call `CreateTokenWithIAM` against it
  - *Scope:* `s3:access_grants:read_write`
- **S3 Access Grants**: an instance linked to Identity Center, a location for `s3://<bucket>/` (backed by `OktaS3DemoAccessGrantsLocationRole`), and **one grant: `DEMO_USER_EMAIL` → READ `demo/*`**.
- **Bucket** with `demo/hello.txt` (granted) and `private/secret.txt` (not granted).

## Step 5: Run the demo

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
delete the `okta-s3-demo` application and the trusted token issuer you created in Step 3 (IAM Identity Center → Settings → Trusted token issuers);
delete both `OktaS3Demo*` IAM roles; empty and delete the bucket.

## Not production-ready

This is a demo. The app doesn't verify the Okta ID token signature itself (AWS verifies it in step 1),
stores tokens in Flask's cookie session, and runs Flask's dev server.
