from app.analyzer import analyze_email, MAX_EMAIL_BYTES
import pytest


def test_reply_to_mismatch_is_reported():
    raw = (
        b"From: Payroll <payroll@bank.example>\r\n"
        b"Reply-To: payroll-help@attacker.example\r\n"
        b"Subject: Salary review\r\n"
        b"Message-ID: <test-1@bank.example>\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Please review the salary details."
    )
    result = analyze_email(raw)
    codes = {finding["code"] for finding in result["findings"]}
    assert "REPLY_TO_DOMAIN_MISMATCH" in codes
    assert result["evidence"]["sha256"]
    assert result["risk_assessment"]["level"] in {"low", "medium", "high"}


def test_extracts_url_without_visiting_it():
    raw = (
        b"From: sender@example.org\r\nSubject: Test\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Please visit http://192.0.2.10/login"
    )
    result = analyze_email(raw)
    assert any(item["ip_literal_host"] for item in result["indicators"]["urls"])
    assert any(f["code"] == "URL_IP_LITERAL" for f in result["findings"])


def test_attachment_is_metadata_only():
    raw = (
        b"From: sender@example.org\r\nSubject: Attachment\r\n"
        b"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n"
        b"--x\r\nContent-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment; filename=invoice.exe\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\nSGVsbG8=\r\n--x--\r\n"
    )
    result = analyze_email(raw)
    assert result["indicators"]["attachments"][0]["suspicious_extension"] is True
    assert any(f["code"] == "RISKY_ATTACHMENT_EXTENSION" for f in result["findings"])


def test_empty_and_oversized_messages_rejected():
    with pytest.raises(ValueError):
        analyze_email(b"")
    with pytest.raises(ValueError):
        analyze_email(b"x" * (MAX_EMAIL_BYTES + 1))


def test_pasted_authentication_headers_are_not_claimed_verified():
    raw = (
        b"From: sender@example.org\r\n"
        b"Authentication-Results: mx.example; dmarc=fail\r\n"
        b"Subject: Test\r\n\r\nBody"
    )
    result = analyze_email(raw)
    finding = next(f for f in result["findings"] if f["code"] == "AUTH_FAILURE_REPORTED")
    assert "not verified" in finding["explanation"]
