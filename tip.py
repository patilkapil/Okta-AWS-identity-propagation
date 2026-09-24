"""Trusted identity propagation: Okta ID token -> file from S3.

The whole AWS side of the demo is in this file. Each function is one hop:

    1. exchange_okta_token()      Okta ID token  -> IAM Identity Center token   (sso-oidc:CreateTokenWithIAM)
    2. identity_enhanced_session() Identity Center token -> IAM role session carrying the user's identity
                                                                                  (sts:AssumeRole + ProvidedContexts)
    3. get_data_access()          identity-enhanced session -> short-lived S3 credentials for *this user*
                                                                                  (s3:GetDataAccess / S3 Access Grants)
    4. read_object()              S3 credentials -> file bytes                   (s3:GetObject)
"""

import base64
import json
import os

import boto3

REGION = os.environ.get("AWS_REGION", "us-east-1")
APP_ROLE_ARN = os.environ["APP_ROLE_ARN"]
IDC_APPLICATION_ARN = os.environ["IDC_APPLICATION_ARN"]

JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
IDENTITY_CENTER_CONTEXT_PROVIDER = "arn:aws:iam::aws:contextProvider/IdentityCenter"


def decode_jwt(token):
    """Return a JWT's claims without verifying it. For display only; AWS does the real verification."""
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def _session_from(creds):
    return boto3.session.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=REGION,
    )


def app_role_session():
    """Plain session as the app's IAM role. This role is the only principal the
    Identity Center application's actor policy allows to call CreateTokenWithIAM."""
    creds = boto3.client("sts", region_name=REGION).assume_role(
        RoleArn=APP_ROLE_ARN, RoleSessionName="okta-s3-demo-app"
    )["Credentials"]
    return _session_from(creds)


def exchange_okta_token(okta_id_token):
    """Step 1: Identity Center checks the JWT's issuer (trusted token issuer) and
    `aud` (the Okta client ID), then maps its `email` claim to an Identity Center user."""
    oidc = app_role_session().client("sso-oidc")
    resp = oidc.create_token_with_iam(
        clientId=IDC_APPLICATION_ARN,
        grantType=JWT_BEARER,
        assertion=okta_id_token,
    )
    identity_context = resp.get("awsAdditionalDetails", {}).get("identityContext")
    if not identity_context:
        identity_context = decode_jwt(resp["idToken"])["sts:identity_context"]
    return resp["idToken"], identity_context


def identity_enhanced_session(identity_context, user_label):
    """Step 2: assume the app role again, this time stamping the user's identity onto the session."""
    creds = boto3.client("sts", region_name=REGION).assume_role(
        RoleArn=APP_ROLE_ARN,
        RoleSessionName=f"okta-{user_label}"[:64],
        ProvidedContexts=[
            {"ProviderArn": IDENTITY_CENTER_CONTEXT_PROVIDER, "ContextAssertion": identity_context}
        ],
    )["Credentials"]
    return _session_from(creds)


def get_data_access(session, bucket, key):
    """Step 3: S3 Access Grants looks up grants for the Identity Center user on the session
    and, if one covers the object, returns credentials scoped to it. No grant means AccessDenied."""
    resp = session.client("s3control").get_data_access(
        AccountId=APP_ROLE_ARN.split(":")[4],
        Target=f"s3://{bucket}/{key}",
        TargetType="Object",
        Permission="READ",
        Privilege="Minimal",
    )
    return resp["Credentials"], resp["MatchedGrantTarget"], resp.get("Grantee", {})


def read_object(creds, bucket, key):
    """Step 4: an ordinary GetObject with the credentials Access Grants handed out."""
    s3 = boto3.client(
        "s3",
        region_name=REGION,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )
    return s3.get_object(Bucket=bucket, Key=key)["Body"].read()


def fetch_file_as_user(okta_id_token, bucket, key):
    """Run all four steps and return (file_bytes, trace) where trace explains each hop."""
    okta_claims = decode_jwt(okta_id_token)
    trace = {"okta": {k: okta_claims.get(k) for k in ("iss", "aud", "sub", "email")}}

    idc_token, identity_context = exchange_okta_token(okta_id_token)
    idc_claims = decode_jwt(idc_token)
    trace["identity_center"] = {k: idc_claims.get(k) for k in ("sub", "aud", "scp", "iss")}

    user_label = (okta_claims.get("email") or okta_claims["sub"]).replace("@", "-at-")
    session = identity_enhanced_session(identity_context, user_label)

    creds, matched_target, grantee = get_data_access(session, bucket, key)
    trace["access_grants"] = {"matched_grant_target": matched_target, "grantee": grantee}

    return read_object(creds, bucket, key), trace
