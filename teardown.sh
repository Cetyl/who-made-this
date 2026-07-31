#!/usr/bin/env bash
# Remove everything: seeded resources, their snapshots, the stack, the SSM key.
# Run this only after the challenge is evaluated if you are linking a live demo.
set -uo pipefail

export AWS_REGION="${1:-us-east-1}"
STACK=who-made-this

if [ -f .seeded-resources ]; then
  # shellcheck disable=SC1091
  source .seeded-resources
  echo "==> Terminating $INST"
  aws ec2 terminate-instances --instance-ids "$INST" --region "$AWS_REGION" >/dev/null

  echo "==> Deleting Purgatory snapshots"
  for SRC in "$VOL" "$INST"; do
    aws ec2 describe-snapshots --owner-ids self --region "$AWS_REGION" \
      --filters "Name=tag:whomadethis:source,Values=$SRC" \
      --query 'Snapshots[].SnapshotId' --output text \
      | tr '\t' '\n' | while read -r S; do
          [ -n "$S" ] && aws ec2 delete-snapshot --snapshot-id "$S" \
            --region "$AWS_REGION" && echo "    deleted $S"
        done
  done

  echo "==> Deleting $VOL"
  aws ec2 delete-volume --volume-id "$VOL" --region "$AWS_REGION" \
    || echo "    volume still attached or already gone, check by hand"
  rm -f .seeded-resources
fi

echo "==> Deleting stack $STACK"
sam delete --stack-name "$STACK" --region "$AWS_REGION" --no-prompts

echo "==> Deleting the signing key"
aws ssm delete-parameter --name /whomadethis/hmac-key --region "$AWS_REGION" \
  || echo "    already gone"

echo "Done. Check the EC2 console for any leftover snapshots."
