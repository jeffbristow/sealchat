#!/usr/bin/env bash
# =====================================================================
# Seal Chat — build/publish-mirror.sh   (1.7.0)
# ---------------------------------------------------------------------
# Puts a release on the GitHub update mirror (jeffbristow/sealchat-updates),
# where Seal Chat and Seal Chat Web look when your website can't be reached.
#
#   ./build/publish-mirror.sh <update.json> <file> [file …]
#
#   update.json   from your website: admin.php → "GitHub update mirror" →
#                 "Download update.json"
#   files         SealChat-x.y.z.sealchat, SealChat-x.y.z.sealchat.sig,
#                 SealChat-Web-a.b.c.zip, SealChat-Web-a.b.c.zip.sig
#                 (the SAME files you uploaded to your website)
#
# Needs: git, signed in to GitHub with push access to the repository.
# What it does:
#   1. reads the version folder out of update.json (…/main/<folder>/<file>)
#   2. checks every file update.json points to is in the list, and that
#      each has its .sig
#   3. copies the files into <folder>/ in the repository, replaces
#      update.json, commits and pushes
# The browser works too: GitHub → the repository → "Add file → Upload
# files" (files up to 25 MB each).
# Never pass the private key (update-signing-key.pem) — it is refused.
#
# Sections: 1 checks · 2 copy · 3 commit + push
# =====================================================================
set -euo pipefail
REPO="${SEALCHAT_MIRROR_REPO:-jeffbristow/sealchat-updates}"

# ---------- 1. checks ----------
[ $# -ge 2 ] || { sed -n '6,16p' "$0"; exit 1; }
JSON="$1"; shift
[ -f "$JSON" ] || { echo "Not found: $JSON"; exit 1; }
for f in "$@"; do
  [ -f "$f" ] || { echo "Not found: $f"; exit 1; }
  case "$f" in *.pem|*.key) echo "Refusing to publish a key file: $f"; exit 1;; esac
  if grep -qE -- "^-----BEGIN [A-Z ]*PRIVATE KEY-----$" "$f" 2>/dev/null; then echo "Refusing: $f contains a private key"; exit 1; fi
done
URLS=$(grep -o '"url": *"[^"]*"' "$JSON" | sed 's/.*"\(https[^"]*\)"/\1/')
[ -n "$URLS" ] || { echo "update.json has no download addresses"; exit 1; }
DIR=$(echo "$URLS" | head -1 | sed -n "s#^https://raw.githubusercontent.com/$REPO/[^/]*/\([^/]*\)/[^/]*\$#\1#p")
[ -n "$DIR" ] || { echo "update.json doesn't point into https://raw.githubusercontent.com/$REPO/main/<folder>/ — check admin.php → GitHub update mirror."; exit 1; }
names=""; for f in "$@"; do names="$names $(basename "$f")"; done
for u in $URLS; do
  n=$(basename "$u" | sed 's/%20/ /g')
  for need in "$n" "$n.sig"; do
    case " $names " in *" $need "*) ;; *) echo "Missing from the list: $need (update.json points to it)"; exit 1;; esac
  done
done
echo "Publishing to $REPO, folder $DIR/:"; for f in "$@"; do echo "  $(basename "$f")"; done

# ---------- 2. copy ----------
TMP=$(mktemp -d)
git clone --depth 1 "https://github.com/$REPO.git" "$TMP/repo"
mkdir -p "$TMP/repo/$DIR"
cp "$@" "$TMP/repo/$DIR/"
cp "$JSON" "$TMP/repo/update.json"

# ---------- 3. commit + push ----------
cd "$TMP/repo"
git add -A
if git diff --cached --quiet; then echo "Nothing new to publish."; exit 0; fi
git commit -m "Update mirror: $DIR" >/dev/null
git push
echo "Published. Check: https://raw.githubusercontent.com/$REPO/main/update.json"
