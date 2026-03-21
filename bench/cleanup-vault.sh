#!/bin/bash
# Remove all bench-folder-* entries from the address book.
# Usage: ./cleanup-vault.sh [api_key] [rustguac_url]
set -e

API_KEY=${1:-""}
RUSTGUAC_URL=${2:-"https://localhost:8089"}

if [ -z "$API_KEY" ]; then
    echo "Usage: $0 <api_key> [rustguac_url]"
    exit 1
fi

CURL="curl -sk -H X-API-Key:${API_KEY}"

echo "Fetching folders..."
FOLDERS=$($CURL "$RUSTGUAC_URL/api/addressbook" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for f in data.get('folders', []):
    if f['name'].startswith('bench-folder-'):
        print(f['scope'] + '/' + f['name'])
" 2>/dev/null)

if [ -z "$FOLDERS" ]; then
    echo "No bench folders found."
    exit 0
fi

COUNT=$(echo "$FOLDERS" | wc -l)
echo "Deleting $COUNT bench folders..."

for folder in $FOLDERS; do
    SCOPE=$(echo "$folder" | cut -d/ -f1)
    NAME=$(echo "$folder" | cut -d/ -f2)
    $CURL -X DELETE "$RUSTGUAC_URL/api/addressbook/folders/$SCOPE/$NAME" -o /dev/null 2>/dev/null
    echo "  Deleted $SCOPE/$NAME"
done

echo "Done."
