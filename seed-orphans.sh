#!/usr/bin/env bash
# Create two genuinely abandoned resources so the scanner has something to find.
# An empty account produces an empty email, which makes a terrible screenshot.
# Writes the ids to .seeded-resources so teardown.sh can clean up.
set -euo pipefail

export AWS_REGION="${1:-us-east-1}"
AZ="${AWS_REGION}a"

echo "==> Creating an unattached, untagged 1 GiB gp3 volume in $AZ"
VOL=$(aws ec2 create-volume --size 1 --volume-type gp3 \
  --availability-zone "$AZ" --region "$AWS_REGION" \
  --query VolumeId --output text)
echo "    $VOL"

echo "==> Creating a stopped, untagged t3.micro"
AMI=$(aws ssm get-parameter --region "$AWS_REGION" \
  --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 \
  --query Parameter.Value --output text)
INST=$(aws ec2 run-instances --image-id "$AMI" --instance-type t3.micro \
  --region "$AWS_REGION" --query 'Instances[0].InstanceId' --output text)
echo "    $INST"
aws ec2 wait instance-running --instance-ids "$INST" --region "$AWS_REGION"
aws ec2 stop-instances --instance-ids "$INST" --region "$AWS_REGION" >/dev/null
echo "    stopping"

printf 'VOL=%s\nINST=%s\nREGION=%s\n' "$VOL" "$INST" "$AWS_REGION" \
  > .seeded-resources

cat <<EOF

Seeded. Wait about 15 minutes before scanning: CloudTrail Event history is not
instant. Confirm attribution is visible with:

  aws cloudtrail lookup-events --region $AWS_REGION \\
    --lookup-attributes AttributeKey=ResourceName,AttributeValue=$VOL \\
    --query 'Events[].[EventName,Username,EventTime]' --output table

Ids saved to .seeded-resources
EOF
