"""
CSPM (Cloud Security Posture Management) Scanner — AttackTrace
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Runs 21+ native AWS checks via boto3 with concurrent execution.
Prowler CLI is used automatically if installed.

Credentials are used per-request and never stored or logged.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import time
import uuid as _uuid_mod
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, AsyncGenerator
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.core.config import get_settings as _get_settings
from app.core.dependencies import get_current_org_id, get_current_user
from app.models.db.user import User

# ── Optional boto3 ────────────────────────────────────────────────────────────
try:
    import boto3  # type: ignore[import]
    import botocore.exceptions  # type: ignore[import]
    _BOTO3_AVAILABLE = True
except ImportError:
    _BOTO3_AVAILABLE = False

# ── Scan history storage (filesystem) ────────────────────────────────────────

def _history_dir(org_id: str) -> Path:
    d = Path(_get_settings().ATTACKTRACE_WORKSPACE_DIR) / "cspm" / org_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def _save_scan_result(org_id: str, record: dict) -> None:
    try:
        path = _history_dir(org_id) / f"{record['id']}.json"
        path.write_text(json.dumps(record, ensure_ascii=False))
    except Exception:
        pass


def _load_history(org_id: str, limit: int = 50) -> list[dict]:
    try:
        files = sorted(
            _history_dir(org_id).glob("*.json"),
            key=lambda f: f.stat().st_mtime,
            reverse=True,
        )[:limit]
        records = []
        for f in files:
            try:
                records.append(json.loads(f.read_text()))
            except Exception:
                pass
        return records
    except Exception:
        return []


def _load_scan(org_id: str, scan_id: str) -> dict | None:
    try:
        path = _history_dir(org_id) / f"{scan_id}.json"
        if path.exists():
            return json.loads(path.read_text())
    except Exception:
        pass
    return None


def _delete_scan(org_id: str, scan_id: str) -> bool:
    try:
        path = _history_dir(org_id) / f"{scan_id}.json"
        if path.exists():
            path.unlink()
            return True
    except Exception:
        pass
    return False


# ── Router ────────────────────────────────────────────────────────────────────

router = APIRouter(prefix="/cspm", tags=["CSPM Scanner"])

# ── Check catalogue ───────────────────────────────────────────────────────────

AWS_CHECKS: list[dict] = [
    # S3
    {"id": "s3_bucket_public_read",    "name": "S3 Bucket Public Read Access",              "severity": "critical", "category": "S3"},
    {"id": "s3_bucket_public_write",   "name": "S3 Bucket Public Write Access",             "severity": "critical", "category": "S3"},
    {"id": "s3_bucket_no_mfa_delete",  "name": "S3 Bucket MFA Delete Not Enabled",          "severity": "medium",   "category": "S3"},
    {"id": "s3_bucket_no_versioning",  "name": "S3 Bucket Versioning Disabled",             "severity": "low",      "category": "S3"},
    {"id": "s3_bucket_no_encryption",  "name": "S3 Bucket Server-Side Encryption Disabled", "severity": "high",     "category": "S3"},
    # IAM
    {"id": "iam_root_access_key",      "name": "Root Account Has Access Key",               "severity": "critical", "category": "IAM"},
    {"id": "iam_mfa_not_enabled",      "name": "IAM User Without MFA",                      "severity": "high",     "category": "IAM"},
    {"id": "iam_admin_policy_attached","name": "Overly Permissive IAM Policy (AdministratorAccess)", "severity": "high", "category": "IAM"},
    {"id": "iam_password_policy_weak", "name": "IAM Password Policy Too Weak",              "severity": "medium",   "category": "IAM"},
    # EC2 / Security Groups
    {"id": "ec2_sg_open_ssh",          "name": "Security Group Allows SSH from 0.0.0.0/0", "severity": "critical", "category": "EC2"},
    {"id": "ec2_sg_open_rdp",          "name": "Security Group Allows RDP from 0.0.0.0/0", "severity": "critical", "category": "EC2"},
    {"id": "ec2_sg_open_all",          "name": "Security Group Allows All Traffic from 0.0.0.0/0", "severity": "critical", "category": "EC2"},
    {"id": "ec2_instance_public_ip",   "name": "EC2 Instance Has Public IP",                "severity": "low",      "category": "EC2"},
    {"id": "ec2_ebs_not_encrypted",    "name": "EBS Volume Not Encrypted",                  "severity": "medium",   "category": "EC2"},
    # RDS
    {"id": "rds_public",               "name": "RDS Instance Publicly Accessible",          "severity": "critical", "category": "RDS"},
    {"id": "rds_no_encryption",        "name": "RDS Instance Not Encrypted",                "severity": "high",     "category": "RDS"},
    {"id": "rds_no_backup",            "name": "RDS Automated Backup Disabled",             "severity": "medium",   "category": "RDS"},
    # CloudTrail
    {"id": "cloudtrail_not_enabled",   "name": "CloudTrail Not Enabled",                   "severity": "high",     "category": "CloudTrail"},
    {"id": "cloudtrail_not_multiregion","name": "CloudTrail Not Multi-Region",              "severity": "medium",   "category": "CloudTrail"},
    # KMS
    {"id": "kms_key_rotation_disabled","name": "KMS Key Rotation Disabled",                 "severity": "medium",   "category": "KMS"},
    # Lambda
    {"id": "lambda_env_vars_secrets",  "name": "Lambda Function Has Secrets in Environment Variables", "severity": "high", "category": "Lambda"},
]

CHECK_CATEGORIES = sorted({c["category"] for c in AWS_CHECKS})

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# ── Pydantic schemas ──────────────────────────────────────────────────────────

class CSPMScanRequest(BaseModel):
    provider: str  # "aws", "azure", "gcp", "kubernetes"
    # AWS
    aws_access_key: str | None = None
    aws_secret_key: str | None = None
    aws_region: str = "us-east-1"
    aws_session_token: str | None = None
    # GCP
    gcp_project_id: str | None = None
    gcp_service_account_key: str | None = None
    # Azure
    azure_subscription_id: str | None = None
    azure_tenant_id: str | None = None
    azure_client_id: str | None = None
    azure_client_secret: str | None = None
    # Filters
    categories: list[str] = []
    severity_filter: str = "medium"  # minimum severity


# ── Helper: build boto3 session ───────────────────────────────────────────────

def _make_boto_session(req: CSPMScanRequest):
    """Return a boto3 Session built from request credentials (never logged)."""
    kwargs: dict = {"region_name": req.aws_region}
    if req.aws_access_key and req.aws_secret_key:
        kwargs["aws_access_key_id"] = req.aws_access_key
        kwargs["aws_secret_access_key"] = req.aws_secret_key
        if req.aws_session_token:
            kwargs["aws_session_token"] = req.aws_session_token
    return boto3.Session(**kwargs)


# ── Remediation text ─────────────────────────────────────────────────────────

_REMEDIATION: dict[str, str] = {
    "s3_bucket_public_read":     "Remove the public ACL and set S3 Block Public Access on the bucket.",
    "s3_bucket_public_write":    "Remove the public write ACL and enable S3 Block Public Access.",
    "s3_bucket_no_mfa_delete":   "Enable MFA Delete on the bucket versioning configuration.",
    "s3_bucket_no_versioning":   "Enable versioning on the S3 bucket.",
    "s3_bucket_no_encryption":   "Enable default SSE-S3 or SSE-KMS encryption on the bucket.",
    "iam_root_access_key":       "Delete root account access keys immediately and use IAM roles instead.",
    "iam_mfa_not_enabled":       "Enforce MFA for all IAM users via an IAM policy condition.",
    "iam_admin_policy_attached": "Replace AdministratorAccess with least-privilege policies.",
    "iam_password_policy_weak":  "Configure a strong IAM account password policy (min 14 chars, complexity, rotation).",
    "ec2_sg_open_ssh":           "Restrict SSH (port 22) to known IP ranges; use AWS Systems Manager Session Manager.",
    "ec2_sg_open_rdp":           "Restrict RDP (port 3389) to known IP ranges; use a bastion host or VPN.",
    "ec2_sg_open_all":           "Remove 0.0.0.0/0 allow-all rules; apply least-privilege security group rules.",
    "ec2_instance_public_ip":    "Place instances in private subnets and route outbound traffic via NAT Gateway.",
    "ec2_ebs_not_encrypted":     "Enable EBS encryption at rest using AWS KMS.",
    "rds_public":                "Disable 'Publicly Accessible' on the RDS instance and move it to a private subnet.",
    "rds_no_encryption":         "Enable encryption at rest for the RDS instance (requires a snapshot restore).",
    "rds_no_backup":             "Enable automated backups with a retention period of at least 7 days.",
    "cloudtrail_not_enabled":    "Create a CloudTrail trail covering all regions with log file validation enabled.",
    "cloudtrail_not_multiregion":"Enable the IsMultiRegionTrail flag on your CloudTrail trail.",
    "kms_key_rotation_disabled": "Enable automatic key rotation on the KMS customer-managed key.",
    "lambda_env_vars_secrets":   "Move secrets to AWS Secrets Manager or SSM Parameter Store and reference them at runtime.",
}


# ── Native AWS checks (boto3) ─────────────────────────────────────────────────

def _run_aws_check(check_id: str, session) -> list[dict]:
    """Execute a single AWS check synchronously. Returns list of findings."""
    findings: list[dict] = []

    def _finding(resource: str, arn: str, description: str, severity: str) -> dict:
        return {
            "check_id": check_id,
            "severity": severity,
            "resource": resource,
            "resource_arn": arn,
            "description": description,
            "remediation": _REMEDIATION.get(check_id, "Review AWS security best practices."),
        }

    try:
        # ── S3 ─────────────────────────────────────────────────────────────
        if check_id.startswith("s3_"):
            s3 = session.client("s3")
            try:
                buckets = s3.list_buckets().get("Buckets", [])
            except Exception:
                return findings

            for b in buckets:
                name = b["Name"]
                arn = f"arn:aws:s3:::{name}"

                if check_id == "s3_bucket_public_read":
                    try:
                        acl = s3.get_bucket_acl(Bucket=name)
                        for grant in acl.get("Grants", []):
                            grantee = grant.get("Grantee", {})
                            uri = grantee.get("URI", "")
                            perm = grant.get("Permission", "")
                            if "AllUsers" in uri and perm in ("READ", "FULL_CONTROL"):
                                findings.append(_finding(name, arn, f"Bucket {name} grants public READ access via ACL.", "critical"))
                    except Exception:
                        pass
                    try:
                        pol_status = s3.get_bucket_policy_status(Bucket=name)
                        if pol_status.get("PolicyStatus", {}).get("IsPublic"):
                            findings.append(_finding(name, arn, f"Bucket {name} has a public bucket policy.", "critical"))
                    except Exception:
                        pass

                elif check_id == "s3_bucket_public_write":
                    try:
                        acl = s3.get_bucket_acl(Bucket=name)
                        for grant in acl.get("Grants", []):
                            uri = grant.get("Grantee", {}).get("URI", "")
                            perm = grant.get("Permission", "")
                            if "AllUsers" in uri and perm in ("WRITE", "WRITE_ACP", "FULL_CONTROL"):
                                findings.append(_finding(name, arn, f"Bucket {name} grants public WRITE access via ACL.", "critical"))
                    except Exception:
                        pass

                elif check_id == "s3_bucket_no_mfa_delete":
                    try:
                        ver = s3.get_bucket_versioning(Bucket=name)
                        if ver.get("MFADelete", "Disabled") != "Enabled":
                            findings.append(_finding(name, arn, f"Bucket {name} does not have MFA Delete enabled.", "medium"))
                    except Exception:
                        pass

                elif check_id == "s3_bucket_no_versioning":
                    try:
                        ver = s3.get_bucket_versioning(Bucket=name)
                        if ver.get("Status", "Suspended") != "Enabled":
                            findings.append(_finding(name, arn, f"Bucket {name} does not have versioning enabled.", "low"))
                    except Exception:
                        pass

                elif check_id == "s3_bucket_no_encryption":
                    try:
                        s3.get_bucket_encryption(Bucket=name)
                    except s3.exceptions.ClientError if hasattr(s3, "exceptions") else Exception:
                        findings.append(_finding(name, arn, f"Bucket {name} has no default server-side encryption.", "high"))
                    except Exception:
                        findings.append(_finding(name, arn, f"Bucket {name} has no default server-side encryption.", "high"))

        # ── IAM ─────────────────────────────────────────────────────────────
        elif check_id.startswith("iam_"):
            iam = session.client("iam")

            if check_id == "iam_root_access_key":
                try:
                    summary = iam.get_account_summary()["SummaryMap"]
                    if summary.get("AccountAccessKeysPresent", 0) > 0:
                        findings.append(_finding("root", "arn:aws:iam::root", "Root account has active access keys.", "critical"))
                except Exception:
                    pass

            elif check_id == "iam_mfa_not_enabled":
                try:
                    paginator = iam.get_paginator("list_users")
                    for page in paginator.paginate():
                        for user in page["Users"]:
                            uname = user["UserName"]
                            mfa_devices = iam.list_mfa_devices(UserName=uname)["MFADevices"]
                            if not mfa_devices:
                                arn = user["Arn"]
                                findings.append(_finding(uname, arn, f"IAM user {uname} has no MFA device.", "high"))
                except Exception:
                    pass

            elif check_id == "iam_admin_policy_attached":
                try:
                    admin_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
                    paginator = iam.get_paginator("list_entities_for_policy")
                    for page in paginator.paginate(PolicyArn=admin_arn):
                        for u in page.get("PolicyUsers", []):
                            findings.append(_finding(u["UserName"], u["UserId"], f"User {u['UserName']} has AdministratorAccess.", "high"))
                        for g in page.get("PolicyGroups", []):
                            findings.append(_finding(g["GroupName"], g["GroupId"], f"Group {g['GroupName']} has AdministratorAccess.", "high"))
                        for r in page.get("PolicyRoles", []):
                            findings.append(_finding(r["RoleName"], r["RoleId"], f"Role {r['RoleName']} has AdministratorAccess.", "high"))
                except Exception:
                    pass

            elif check_id == "iam_password_policy_weak":
                try:
                    pol = iam.get_account_password_policy()["PasswordPolicy"]
                    issues = []
                    if pol.get("MinimumPasswordLength", 0) < 14:
                        issues.append("min length < 14")
                    if not pol.get("RequireUppercaseCharacters"):
                        issues.append("no uppercase requirement")
                    if not pol.get("RequireLowercaseCharacters"):
                        issues.append("no lowercase requirement")
                    if not pol.get("RequireNumbers"):
                        issues.append("no number requirement")
                    if not pol.get("RequireSymbols"):
                        issues.append("no symbol requirement")
                    if issues:
                        findings.append(_finding("account", "arn:aws:iam::password-policy", f"Password policy issues: {', '.join(issues)}.", "medium"))
                except Exception:
                    # No password policy set at all
                    findings.append(_finding("account", "arn:aws:iam::password-policy", "No IAM account password policy is configured.", "medium"))

        # ── EC2 / Security Groups ───────────────────────────────────────────
        elif check_id.startswith("ec2_sg_"):
            ec2 = session.client("ec2")
            try:
                paginator = ec2.get_paginator("describe_security_groups")
                for page in paginator.paginate():
                    for sg in page["SecurityGroups"]:
                        sg_id = sg["GroupId"]
                        sg_name = sg.get("GroupName", sg_id)
                        arn = f"arn:aws:ec2:{session.region_name}::security-group/{sg_id}"
                        for rule in sg.get("IpPermissions", []):
                            from_port = rule.get("FromPort", -1)
                            to_port = rule.get("ToPort", -1)
                            for ip_range in rule.get("IpRanges", []) + rule.get("Ipv6Ranges", []):
                                cidr = ip_range.get("CidrIp") or ip_range.get("CidrIpv6", "")
                                if cidr in ("0.0.0.0/0", "::/0"):
                                    if check_id == "ec2_sg_open_ssh" and from_port <= 22 <= to_port:
                                        findings.append(_finding(sg_name, arn, f"SG {sg_name} allows SSH from {cidr}.", "critical"))
                                    elif check_id == "ec2_sg_open_rdp" and from_port <= 3389 <= to_port:
                                        findings.append(_finding(sg_name, arn, f"SG {sg_name} allows RDP from {cidr}.", "critical"))
                                    elif check_id == "ec2_sg_open_all" and from_port == -1 and to_port == -1:
                                        findings.append(_finding(sg_name, arn, f"SG {sg_name} allows all traffic from {cidr}.", "critical"))
            except Exception:
                pass

        elif check_id == "ec2_instance_public_ip":
            ec2 = session.client("ec2")
            try:
                paginator = ec2.get_paginator("describe_instances")
                for page in paginator.paginate():
                    for r in page["Reservations"]:
                        for inst in r["Instances"]:
                            if inst.get("PublicIpAddress") and inst.get("State", {}).get("Name") == "running":
                                iid = inst["InstanceId"]
                                arn = f"arn:aws:ec2:{session.region_name}::instance/{iid}"
                                findings.append(_finding(iid, arn, f"Instance {iid} has public IP {inst['PublicIpAddress']}.", "low"))
            except Exception:
                pass

        elif check_id == "ec2_ebs_not_encrypted":
            ec2 = session.client("ec2")
            try:
                paginator = ec2.get_paginator("describe_volumes")
                for page in paginator.paginate():
                    for vol in page["Volumes"]:
                        if not vol.get("Encrypted"):
                            vid = vol["VolumeId"]
                            arn = f"arn:aws:ec2:{session.region_name}::volume/{vid}"
                            findings.append(_finding(vid, arn, f"EBS volume {vid} is not encrypted.", "medium"))
            except Exception:
                pass

        # ── RDS ─────────────────────────────────────────────────────────────
        elif check_id.startswith("rds_"):
            rds = session.client("rds")
            try:
                paginator = rds.get_paginator("describe_db_instances")
                for page in paginator.paginate():
                    for db in page["DBInstances"]:
                        did = db["DBInstanceIdentifier"]
                        arn = db["DBInstanceArn"]
                        if check_id == "rds_public" and db.get("PubliclyAccessible"):
                            findings.append(_finding(did, arn, f"RDS instance {did} is publicly accessible.", "critical"))
                        elif check_id == "rds_no_encryption" and not db.get("StorageEncrypted"):
                            findings.append(_finding(did, arn, f"RDS instance {did} storage is not encrypted.", "high"))
                        elif check_id == "rds_no_backup" and db.get("BackupRetentionPeriod", 0) == 0:
                            findings.append(_finding(did, arn, f"RDS instance {did} has automated backup disabled.", "medium"))
            except Exception:
                pass

        # ── CloudTrail ───────────────────────────────────────────────────────
        elif check_id.startswith("cloudtrail_"):
            ct = session.client("cloudtrail")
            try:
                trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
                if check_id == "cloudtrail_not_enabled":
                    if not trails:
                        findings.append(_finding("account", "arn:aws:cloudtrail::trail", "No CloudTrail trails are configured.", "high"))
                    else:
                        for t in trails:
                            status_resp = ct.get_trail_status(Name=t["TrailARN"])
                            if not status_resp.get("IsLogging"):
                                findings.append(_finding(t["Name"], t["TrailARN"], f"CloudTrail trail {t['Name']} is not logging.", "high"))
                elif check_id == "cloudtrail_not_multiregion":
                    if not trails:
                        findings.append(_finding("account", "arn:aws:cloudtrail::trail", "No CloudTrail trails configured.", "medium"))
                    else:
                        for t in trails:
                            if not t.get("IsMultiRegionTrail"):
                                findings.append(_finding(t["Name"], t["TrailARN"], f"CloudTrail trail {t['Name']} is not multi-region.", "medium"))
            except Exception:
                pass

        # ── KMS ─────────────────────────────────────────────────────────────
        elif check_id == "kms_key_rotation_disabled":
            kms = session.client("kms")
            try:
                paginator = kms.get_paginator("list_keys")
                for page in paginator.paginate():
                    for key in page["Keys"]:
                        kid = key["KeyId"]
                        try:
                            meta = kms.describe_key(KeyId=kid)["KeyMetadata"]
                            if meta.get("KeyManager") != "AWS" and meta.get("KeyState") == "Enabled":
                                rotation = kms.get_key_rotation_status(KeyId=kid)
                                if not rotation.get("KeyRotationEnabled"):
                                    arn = meta["Arn"]
                                    alias = meta.get("Description", kid)[:40]
                                    findings.append(_finding(alias, arn, f"KMS key {kid} does not have automatic rotation enabled.", "medium"))
                        except Exception:
                            pass
            except Exception:
                pass

        # ── Lambda ───────────────────────────────────────────────────────────
        elif check_id == "lambda_env_vars_secrets":
            lm = session.client("lambda")
            SECRET_PATTERNS = ["secret", "password", "passwd", "token", "api_key", "apikey", "private_key", "access_key"]
            try:
                paginator = lm.get_paginator("list_functions")
                for page in paginator.paginate():
                    for fn in page["Functions"]:
                        fname = fn["FunctionName"]
                        arn = fn["FunctionArn"]
                        env_vars = fn.get("Environment", {}).get("Variables", {})
                        for k in env_vars:
                            if any(p in k.lower() for p in SECRET_PATTERNS):
                                findings.append(_finding(fname, arn, f"Lambda function {fname} has a suspicious env var: {k}.", "high"))
                                break
            except Exception:
                pass

    except Exception:
        # Broad catch — never surface credential errors to logs
        pass

    return findings


# ── Prowler integration ───────────────────────────────────────────────────────

async def _run_prowler(req: CSPMScanRequest) -> list[dict] | None:
    """Run Prowler CLI if available and return findings in our format."""
    if not shutil.which("prowler"):
        return None
    import tempfile, os, subprocess  # noqa: E401

    out_dir = tempfile.mkdtemp(prefix="prowler_")
    env = os.environ.copy()
    if req.aws_access_key:
        env["AWS_ACCESS_KEY_ID"] = req.aws_access_key
    if req.aws_secret_key:
        env["AWS_SECRET_ACCESS_KEY"] = req.aws_secret_key
    if req.aws_session_token:
        env["AWS_SESSION_TOKEN"] = req.aws_session_token
    if req.aws_region:
        env["AWS_DEFAULT_REGION"] = req.aws_region

    cmd = ["prowler", "aws", "-M", "json", "-o", out_dir, "--filter-severity", "critical", "high", "medium"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            env=env,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.communicate(), timeout=600)
    except Exception:
        return None

    # Find the JSON output file
    findings: list[dict] = []
    try:
        import glob as _glob
        for jf in _glob.glob(f"{out_dir}/**/*.json", recursive=True):
            raw = json.loads(Path(jf).read_text(errors="replace"))
            items = raw if isinstance(raw, list) else raw.get("results", [])
            for item in items:
                status = (item.get("Status") or item.get("status", "")).upper()
                if status != "FAIL":
                    continue
                severity = (item.get("Severity") or item.get("severity", "medium")).lower()
                findings.append({
                    "check_id": item.get("CheckID") or item.get("check_id", "prowler_check"),
                    "severity": severity,
                    "resource": item.get("ResourceId") or item.get("resource", "unknown"),
                    "resource_arn": item.get("ResourceArn") or item.get("resource_arn", ""),
                    "description": item.get("Description") or item.get("description", ""),
                    "remediation": item.get("Remediation", {}).get("Recommendation", {}).get("Text", "") if isinstance(item.get("Remediation"), dict) else str(item.get("Remediation", "")),
                })
    except Exception:
        pass

    try:
        import shutil as _sh
        _sh.rmtree(out_dir, ignore_errors=True)
    except Exception:
        pass

    return findings


# ── Severity filter helper ────────────────────────────────────────────────────

def _above_threshold(severity: str, threshold: str) -> bool:
    return SEVERITY_ORDER.get(severity, 99) <= SEVERITY_ORDER.get(threshold, 99)


# ── SSE stream generator ──────────────────────────────────────────────────────

def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


async def _cspm_stream(
    scan_id: str,
    req: CSPMScanRequest,
    org_id: str,
) -> AsyncGenerator[str, None]:
    started = time.time()
    all_findings: list[dict] = []
    checks_run = 0
    by_severity: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    # ── Determine which checks to run ────────────────────────────────────────
    if req.provider == "aws":
        checks = [c for c in AWS_CHECKS if not req.categories or c["category"] in req.categories]
    else:
        # GCP / Azure / Kubernetes — placeholder; emit an informational message
        yield _sse("error", {
            "message": f"Native checks for provider '{req.provider}' are not yet implemented. "
                       "Install Prowler CLI for GCP/Azure support.",
        })
        return

    # ── Try Prowler first (AWS only) ─────────────────────────────────────────
    prowler_findings = None
    if shutil.which("prowler") and req.provider == "aws":
        yield _sse("status", {"message": "Prowler CLI detected — running full Prowler scan..."})
        prowler_findings = await _run_prowler(req)

    if prowler_findings is not None:
        # Emit Prowler findings grouped by check
        for f in prowler_findings:
            if _above_threshold(f["severity"], req.severity_filter):
                yield _sse("finding", f)
                all_findings.append(f)
                by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
        checks_run = len(checks)
    else:
        # ── Native boto3 checks ───────────────────────────────────────────────
        if not _BOTO3_AVAILABLE:
            yield _sse("error", {"message": "boto3 is not installed. Run: pip install boto3"})
            return

        try:
            session = _make_boto_session(req)
        except Exception as exc:
            yield _sse("error", {"message": f"Failed to create AWS session: {exc}"})
            return

        loop = asyncio.get_event_loop()
        executor = ThreadPoolExecutor(max_workers=6)

        async def _run_check_async(check: dict) -> list[dict]:
            return await loop.run_in_executor(executor, _run_aws_check, check["id"], session)

        # Run checks in batches of 5 concurrently
        BATCH = 5
        for i in range(0, len(checks), BATCH):
            batch = checks[i : i + BATCH]
            # Announce start of each check in the batch
            for c in batch:
                yield _sse("check_start", {"check_id": c["id"], "check_name": c["name"]})

            results = await asyncio.gather(*[_run_check_async(c) for c in batch])

            for c, raw_findings in zip(batch, results):
                batch_findings = [f for f in raw_findings if _above_threshold(f["severity"], req.severity_filter)]
                for f in batch_findings:
                    yield _sse("finding", f)
                    all_findings.append(f)
                    by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
                yield _sse("check_complete", {"check_id": c["id"], "findings_count": len(batch_findings)})
                checks_run += 1

        executor.shutdown(wait=False)

    # ── Save to history ───────────────────────────────────────────────────────
    duration = round(time.time() - started, 1)
    record = {
        "id": scan_id,
        "provider": req.provider,
        "region": req.aws_region if req.provider == "aws" else None,
        "categories": req.categories,
        "severity_filter": req.severity_filter,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": duration,
        "checks_run": checks_run,
        "total_findings": len(all_findings),
        "by_severity": by_severity,
        "findings": all_findings,
        "prowler_used": prowler_findings is not None,
    }
    _save_scan_result(org_id, record)

    yield _sse("complete", {
        "scan_id": scan_id,
        "total_findings": len(all_findings),
        "by_severity": by_severity,
        "checks_run": checks_run,
        "duration_seconds": duration,
        "prowler_used": prowler_findings is not None,
    })


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/history", summary="List CSPM scan history")
async def list_history(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
) -> dict:
    records = _load_history(str(org_id))
    # Strip findings list from summary response for performance
    summaries = [
        {k: v for k, v in r.items() if k != "findings"}
        for r in records
    ]
    return {"items": summaries, "total": len(summaries)}


@router.get("/history/{scan_id}", summary="Get single CSPM scan")
async def get_scan(
    scan_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
) -> dict:
    record = _load_scan(str(org_id), scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    return record


@router.delete("/history/{scan_id}", summary="Delete CSPM scan")
async def delete_scan(
    scan_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
) -> dict:
    ok = _delete_scan(str(org_id), scan_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"deleted": True}


@router.get("/checks", summary="List available CSPM check categories")
async def list_checks(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
) -> dict:
    return {
        "provider": "aws",
        "categories": CHECK_CATEGORIES,
        "checks": AWS_CHECKS,
        "total": len(AWS_CHECKS),
    }


@router.post("/scan", summary="Start a CSPM scan (SSE stream)")
async def start_scan(
    req: CSPMScanRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
) -> StreamingResponse:
    if req.provider not in ("aws", "azure", "gcp", "kubernetes"):
        raise HTTPException(status_code=400, detail="provider must be one of: aws, azure, gcp, kubernetes")

    scan_id = str(_uuid_mod.uuid4())

    return StreamingResponse(
        _cspm_stream(scan_id, req, str(org_id)),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "X-Scan-Id": scan_id,
        },
    )
