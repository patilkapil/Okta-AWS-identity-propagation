"""One-time AWS setup for the Okta -> S3 identity propagation demo.

Prerequisites (see README): IAM Identity Center is enabled, and the demo user already
exists in it (provisioned from Okta via SCIM). Safe to re-run: it reuses anything
it already created.

Run:  python setup_aws.py
"""

import json
import os
import time

import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv

load_dotenv()

REGION = os.environ.get("AWS_REGION", "us-east-1")
OKTA_ISSUER = os.environ["OKTA_ISSUER"].rstrip("/")
OKTA_CLIENT_ID = os.environ["OKTA_CLIENT_ID"]
BUCKET = os.environ["S3_BUCKET"]
DEMO_USER_EMAIL = os.environ["DEMO_USER_EMAIL"]
GRANT_PREFIX = "demo/*"
DEMO_KEY = "demo/hello.txt"

APP_ROLE_NAME = "OktaS3DemoAppRole"
LOCATION_ROLE_NAME = "OktaS3DemoAccessGrantsLocationRole"
TTI_NAME = "okta-s3-demo-issuer"
IDC_APP_NAME = "okta-s3-demo"

iam = boto3.client("iam")
s3 = boto3.client("s3", region_name=REGION)
s3control = boto3.client("s3control", region_name=REGION)
sso_admin = boto3.client("sso-admin", region_name=REGION)
identitystore = boto3.client("identitystore", region_name=REGION)
ACCOUNT_ID = boto3.client("sts").get_caller_identity()["Account"]


def step(msg):
    print(f"\n==> {msg}")


def ensure_role(name, trust, policy):
    try:
        arn = iam.get_role(RoleName=name)["Role"]["Arn"]
        iam.update_assume_role_policy(RoleName=name, PolicyDocument=json.dumps(trust))
        created = False
    except iam.exceptions.NoSuchEntityException:
        arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
        created = True
    iam.put_role_policy(RoleName=name, PolicyName="demo", PolicyDocument=json.dumps(policy))
    print(f"    {name}: {arn}")
    return arn, created


# --- IAM Identity Center instance -------------------------------------------------
step("Finding IAM Identity Center instance")
instances = sso_admin.list_instances()["Instances"]
if not instances:
    raise SystemExit(f"IAM Identity Center is not enabled in {REGION}. Enable it first (see README).")
INSTANCE_ARN = instances[0]["InstanceArn"]
IDENTITY_STORE_ID = instances[0]["IdentityStoreId"]
print(f"    {INSTANCE_ARN} (identity store {IDENTITY_STORE_ID})")

step(f"Looking up Identity Center user {DEMO_USER_EMAIL}")
user_id = None
for path in ("emails.value", "userName"):
    try:
        user_id = identitystore.get_user_id(
            IdentityStoreId=IDENTITY_STORE_ID,
            AlternateIdentifier={"UniqueAttribute": {"AttributePath": path, "AttributeValue": DEMO_USER_EMAIL}},
        )["UserId"]
        break
    except ClientError:
        pass
if not user_id:
    raise SystemExit(f"{DEMO_USER_EMAIL} is not in IAM Identity Center yet. Assign them to the "
                     "AWS IAM Identity Center app in Okta so SCIM pushes them over, then re-run.")
print(f"    user id {user_id}")

# --- S3 bucket + demo file --------------------------------------------------------
step(f"Creating bucket s3://{BUCKET} and uploading {DEMO_KEY}")
try:
    if REGION == "us-east-1":
        s3.create_bucket(Bucket=BUCKET)
    else:
        s3.create_bucket(Bucket=BUCKET, CreateBucketConfiguration={"LocationConstraint": REGION})
except (s3.exceptions.BucketAlreadyOwnedByYou, s3.exceptions.BucketAlreadyExists):
    pass
s3.put_object(Bucket=BUCKET, Key=DEMO_KEY,
              Body=b"Hello from S3! If you can read this, your Okta identity was propagated to AWS.\n")
s3.put_object(Bucket=BUCKET, Key="private/secret.txt",
              Body=b"Nobody has a grant for this prefix, so this should always be denied.\n")

# --- IAM roles --------------------------------------------------------------------
step("Creating IAM roles")
app_role_arn, app_created = ensure_role(
    APP_ROLE_NAME,
    # Your local AWS credentials assume this role. sts:SetContext is what lets the
    # app attach the Identity Center identity context to the role session.
    trust={"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT_ID}:root"},
        "Action": ["sts:AssumeRole", "sts:SetContext"],
    }]},
    # CreateTokenWithIAM is added below, scoped to the Identity Center application once it exists.
    policy={"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "s3:GetDataAccess", "Resource": "*"},
    ]},
)
location_role_arn, loc_created = ensure_role(
    LOCATION_ROLE_NAME,
    # S3 Access Grants assumes this role to mint the per-user S3 credentials.
    trust={"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "access-grants.s3.amazonaws.com"},
        "Action": ["sts:AssumeRole", "sts:SetSourceIdentity", "sts:SetContext"],
        "Condition": {"StringEquals": {"aws:SourceAccount": ACCOUNT_ID}},
    }]},
    policy={"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": f"arn:aws:s3:::{BUCKET}/*"},
        {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": f"arn:aws:s3:::{BUCKET}"},
    ]},
)
if app_created or loc_created:
    print("    waiting 15s for IAM to propagate...")
    time.sleep(15)

# --- Trusted token issuer (points at Okta) ----------------------------------------
step(f"Creating trusted token issuer for {OKTA_ISSUER}")
tti_arn = next((t["TrustedTokenIssuerArn"] for t in
                sso_admin.list_trusted_token_issuers(InstanceArn=INSTANCE_ARN)["TrustedTokenIssuers"]
                if t["Name"] == TTI_NAME), None)
if not tti_arn:
    tti_arn = sso_admin.create_trusted_token_issuer(
        InstanceArn=INSTANCE_ARN,
        Name=TTI_NAME,
        TrustedTokenIssuerType="OIDC_JWT",
        TrustedTokenIssuerConfiguration={"OidcJwtConfiguration": {
            "IssuerUrl": OKTA_ISSUER,
            # Okta's `email` claim is matched against the Identity Center user's email.
            "ClaimAttributePath": "email",
            "IdentityStoreAttributePath": "emails.value",
            "JwksRetrievalOption": "OPEN_ID_DISCOVERY",
        }},
    )["TrustedTokenIssuerArn"]
print(f"    {tti_arn}")

# --- Customer managed application (the AWS-side twin of the Okta app) -------------
step("Creating Identity Center customer managed application")
app_arn = next((a["ApplicationArn"] for a in
                sso_admin.list_applications(InstanceArn=INSTANCE_ARN)["Applications"]
                if a["Name"] == IDC_APP_NAME), None)
if not app_arn:
    app_arn = sso_admin.create_application(
        InstanceArn=INSTANCE_ARN,
        ApplicationProviderArn="arn:aws:sso::aws:applicationProvider/custom",
        Name=IDC_APP_NAME,
        Description="Okta -> S3 trusted identity propagation demo",
        PortalOptions={"Visibility": "DISABLED"},
    )["ApplicationArn"]
print(f"    {app_arn}")

sso_admin.put_application_assignment_configuration(ApplicationArn=app_arn, AssignmentRequired=False)

# This is the link between the two apps: accept JWTs from the Okta issuer whose
# `aud` is the Okta app's client ID.
sso_admin.put_application_grant(
    ApplicationArn=app_arn,
    GrantType="urn:ietf:params:oauth:grant-type:jwt-bearer",
    Grant={"JwtBearer": {"AuthorizedTokenIssuers": [
        {"TrustedTokenIssuerArn": tti_arn, "AuthorizedAudiences": [OKTA_CLIENT_ID]}
    ]}},
)
# Only the app role may present tokens to this application.
sso_admin.put_application_authentication_method(
    ApplicationArn=app_arn,
    AuthenticationMethodType="IAM",
    AuthenticationMethod={"Iam": {"ActorPolicy": {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": app_role_arn},
            "Action": "sso-oauth:CreateTokenWithIAM",
            "Resource": "*",
        }],
    }}},
)
# ...and the app role may call the token exchange only against this application.
iam.put_role_policy(RoleName=APP_ROLE_NAME, PolicyName="demo", PolicyDocument=json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": "sso-oauth:CreateTokenWithIAM", "Resource": app_arn},
        {"Effect": "Allow", "Action": "s3:GetDataAccess", "Resource": "*"},
    ],
}))
# Tokens issued for this app may be used with S3 Access Grants.
sso_admin.put_application_access_scope(ApplicationArn=app_arn, Scope="s3:access_grants:read_write")
print("    grant (issuer + audience), actor policy and s3:access_grants scope configured")

# --- S3 Access Grants -------------------------------------------------------------
step("Configuring S3 Access Grants")
try:
    instance = s3control.get_access_grants_instance(AccountId=ACCOUNT_ID)
    if instance.get("IdentityCenterArn") != INSTANCE_ARN:
        s3control.associate_access_grants_identity_center(AccountId=ACCOUNT_ID, IdentityCenterArn=INSTANCE_ARN)
except ClientError as e:
    if e.response["Error"]["Code"] != "AccessGrantsInstanceNotExistsError":
        raise
    s3control.create_access_grants_instance(AccountId=ACCOUNT_ID, IdentityCenterArn=INSTANCE_ARN)

location_scope = f"s3://{BUCKET}/"
locations = s3control.list_access_grants_locations(AccountId=ACCOUNT_ID, LocationScope=location_scope)
location_id = next((l["AccessGrantsLocationId"] for l in locations["AccessGrantsLocationsList"]), None)
if not location_id:
    location_id = s3control.create_access_grants_location(
        AccountId=ACCOUNT_ID, LocationScope=location_scope, IAMRoleArn=location_role_arn,
    )["AccessGrantsLocationId"]
print(f"    location {location_scope} ({location_id})")

existing = s3control.list_access_grants(
    AccountId=ACCOUNT_ID, GranteeType="DIRECTORY_USER", GranteeIdentifier=user_id,
)["AccessGrantsList"]
if not any(g.get("GrantScope") == f"s3://{BUCKET}/{GRANT_PREFIX}" for g in existing):
    s3control.create_access_grant(
        AccountId=ACCOUNT_ID,
        AccessGrantsLocationId=location_id,
        AccessGrantsLocationConfiguration={"S3SubPrefix": GRANT_PREFIX},
        Grantee={"GranteeType": "DIRECTORY_USER", "GranteeIdentifier": user_id},
        Permission="READ",
    )
print(f"    {DEMO_USER_EMAIL} -> READ s3://{BUCKET}/{GRANT_PREFIX}")

print(f"""
Done. Add these to your .env:

APP_ROLE_ARN={app_role_arn}
IDC_APPLICATION_ARN={app_arn}
""")
