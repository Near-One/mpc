#!/bin/bash

# Usage: ./upload_secrets.sh -d DEST_PROJECT -f SECRETS_FILE.txt

# Secret file format:
# multichain-account-sk-mainnet-0=foo
# multichain-account-sk-mainnet-1=bar
# multichain-account-sk-mainnet-2=baz

# Should be a .txt file ^

# DO NOT COMMIT THE TXT FILE TO SOURCE CONTROL, DELETE AFTER SECRETS HAVE BEEN CREATED AND NETWORK IS FUNCTIONAL

while getopts ":d:f:" opt; do
  case $opt in
    d) DEST_PROJECT="$OPTARG"
    ;;
    f) SECRETS_FILE="$OPTARG"
    ;;
    \?) echo "Invalid option -$OPTARG" >&2
        exit 1
    ;;
  esac
done

if [ -z "$DEST_PROJECT" ] || [ -z "$SECRETS_FILE" ]; then
  echo "Usage: $0 -d DEST_PROJECT -f SECRETS_FILE"
  exit 1
fi

while read -r line || [ -n "$line" ]; do
  line=$(echo "$line" | xargs)

  SECRET_NAME=$(echo "$line" | cut -d '=' -f 1)
  SECRET_VALUE=$(echo "$line" | cut -d '=' -f 2-)
  
  echo "Creating secret: $SECRET_NAME in project: $DEST_PROJECT"
  printf "%s" "$SECRET_VALUE" | gcloud secrets create "$SECRET_NAME" --data-file=- --project="$DEST_PROJECT" --replication-policy="automatic"
  
  if [ $? -ne 0 ]; then
    echo "Failed to create secret: $SECRET_NAME in project: $DEST_PROJECT"
    continue
  fi
done < "$SECRETS_FILE"

echo "Secret creation completed."
