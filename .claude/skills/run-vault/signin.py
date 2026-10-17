"""Signs a vault account in to the local vault through the real sign-in (password, then a real
TOTP code) and writes a Netscape cookie jar that `curl -b` accepts.

Usage:  python3 -I signin.py <username> <cookie-jar-path>
Env:    EV_PASSWORD     the account's password
        EV_SQL_PASSWORD the SQL Server sa password (to read the account's TOTP secret)
        EV_SQL_CONTAINER the SQL Server container (default: eclipsvault-db)
        EV_BASE_URL     the vault (default: https://localhost:7443)

Exits non-zero, saying why, when the sign-in does not end in a session.
"""
import base64, hashlib, hmac, http.cookiejar, os, re, ssl, struct, subprocess, sys, time
import urllib.parse, urllib.request

BASE = os.environ.get("EV_BASE_URL", "https://localhost:7443")


def totp_secret(username):
    # sqlcmd variables are textual substitution, so the name is checked before it reaches the query.
    if not re.fullmatch(r"[A-Za-z0-9._@-]+", username):
        sys.exit(f"Refusing an unusual username: {username!r}")
    out = subprocess.run(
        ["docker", "exec", os.environ.get("EV_SQL_CONTAINER", "eclipsvault-db"),
         "/opt/mssql-tools18/bin/sqlcmd", "-S", "localhost", "-U", "sa", "-P", os.environ["EV_SQL_PASSWORD"],
         "-C", "-d", "EclipsVaultUmbraDb", "-h", "-1", "-W", "-v", f"user={username}",
         "-Q", "SET NOCOUNT ON; SELECT TotpSecret FROM Users WHERE Username = '$(user)'"],
        capture_output=True, text=True, check=True).stdout.strip()
    if not re.fullmatch(r"[A-Z2-7]+=*", out):
        sys.exit(f"No TOTP secret found for {username!r}.")
    return out


def totp(secret):
    # A code is accepted once per 30-second step (replay protection), so never use one about to expire.
    if 30 - time.time() % 30 < 5:
        time.sleep(6)
    digest = hmac.new(base64.b32decode(secret), struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return f"{(struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000:06d}"


def main():
    username, jar_path = sys.argv[1:3]
    # Certificate checks are off only for a loopback vault, whose dev certificate is self-signed.
    if urllib.parse.urlsplit(BASE).hostname not in ("localhost", "127.0.0.1", "::1"):
        sys.exit(f"Refusing {BASE}: this script is for a local vault only.")
    secret = totp_secret(username)
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))

    def post_form(path, fields):
        page = opener.open(BASE + path).read().decode()
        token = re.search(r'name="__RequestVerificationToken" type="hidden" value="([^"]+)"', page).group(1)
        return opener.open(BASE + path, urllib.parse.urlencode({**fields, "__RequestVerificationToken": token}).encode())

    if "/Account/Totp" not in post_form("/Account/Login", {"Username": username, "Password": os.environ["EV_PASSWORD"]}).geturl():
        sys.exit("The password step did not reach the TOTP page: wrong password, a locked account, or the sign-in throttle.")
    landed = post_form("/Account/Totp", {"Code": totp(secret)}).geturl()
    if "/Account/" in landed or not any(c.name == "EclipsVault.Session" for c in jar):
        sys.exit(f"The TOTP step did not create a session (ended at {landed}).")

    # Written by hand: Python's MozillaCookieJar saves `localhost` as `localhost.local`, which curl never sends.
    with open(jar_path, "w") as f:
        f.write("# Netscape HTTP Cookie File\n")
        for c in jar:
            f.write(f"{c.domain.removesuffix('.local')}\tFALSE\t{c.path}\t{'TRUE' if c.secure else 'FALSE'}\t0\t{c.name}\t{c.value}\n")
    print(f"Signed in as {username}; landed on {landed}; cookies in {jar_path}")


main()
