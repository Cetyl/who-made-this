#!/usr/bin/env bash
# Who Made This? one-shot setup, deploy and smoke test.
# Usage:  ./run.sh you@example.com [region]
set -euo pipefail

EMAIL="${1:?usage: ./run.sh you@example.com [region]}"
export AWS_REGION="${2:-us-east-1}"
STACK=who-made-this
PARAM=/whomadethis/hmac-key

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

say "Account and region"
aws sts get-caller-identity --query '[Account,Arn]' --output text
echo "region: $AWS_REGION"

say "Checking SES verification for $EMAIL"
STATUS=$(aws ses get-identity-verification-attributes \
  --identities "$EMAIL" --region "$AWS_REGION" \
  --query "VerificationAttributes.\"$EMAIL\".VerificationStatus" \
  --output text 2>/dev/null || echo "None")
if [ "$STATUS" != "Success" ]; then
  echo "SES status for $EMAIL is: $STATUS"
  aws ses verify-email-identity --email-address "$EMAIL" --region "$AWS_REGION"
  echo ">> Verification email sent. Click the link, then re-run this script."
  echo ">> A new SES account is in the sandbox, so sender AND recipient must be verified."
  exit 1
fi
echo "SES verified."

say "Storing the HMAC signing key in Parameter Store (free, SecureString)"
if aws ssm get-parameter --name "$PARAM" --region "$AWS_REGION" >/dev/null 2>&1; then
  echo "already exists, leaving it alone"
else
  aws ssm put-parameter --name "$PARAM" --type SecureString \
    --value "$(openssl rand -base64 48)" --region "$AWS_REGION"
fi

say "Validating and building"
sam validate --lint --region "$AWS_REGION"
sam build

say "Deploying"
sam deploy \
  --stack-name "$STACK" \
  --region "$AWS_REGION" \
  --resolve-s3 \
  --capabilities CAPABILITY_IAM \
  --no-confirm-changeset \
  --no-fail-on-empty-changeset \
  --parameter-overrides \
    "SenderEmail=$EMAIL" \
    "RecipientEmail=$EMAIL"

say "Stack outputs"
aws cloudformation describe-stacks --stack-name "$STACK" --region "$AWS_REGION" \
  --query 'Stacks[0].Outputs[].[OutputKey,OutputValue]' --output table

SCANNER=$(aws cloudformation describe-stacks --stack-name "$STACK" \
  --region "$AWS_REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='ScannerName'].OutputValue" --output text)

say "Running a scan now: $SCANNER"
aws lambda invoke --function-name "$SCANNER" --region "$AWS_REGION" \
  --cli-binary-format raw-in-base64-out --payload '{}' /tmp/wmt-out.json >/dev/null
cat /tmp/wmt-out.json; echo

say "Done. Check $EMAIL for the digest."
echo "Logs:     sam logs -n ScannerFunction --stack-name $STACK --region $AWS_REGION"
echo "Teardown: ./teardown.sh $AWS_REGION"
