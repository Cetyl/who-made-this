# Weekend Annoying Task Challenge: Who Made This?

> **Builder Center metadata**
> **Title (47 chars):** Weekend Annoying Task Challenge: Who Made This?
> **Description (152 chars):** A weekly agent that finds abandoned AWS resources, names who created them from CloudTrail, and parks them in a reversible Purgatory instead of deleting.
> **Tags:** #productivity #challenge #aws-free-tier #application
>
> Placeholders below are marked `[[LIKE THIS]]`. Replace every one before publishing.

---

Every quarter, somebody on my team has to open the AWS console and answer a question nobody can answer: is this still needed?

There is a stopped `t3.micro` from March. An unattached 100 GiB volume. Three Elastic IPs pointing at nothing. No `Owner` tag on any of them. The person who created them may not work here any more. And so the resources stay, month after month, because deleting something you cannot explain feels worse than paying for it. That instinct is correct, by the way. I have watched someone terminate an "obviously dead" instance and then spend a day discovering it was a licence server.

So the annoying task is not really the cleanup. It is the archaeology. Working out who made this, and when, and whether anyone still cares.

This weekend I built **Who Made This?** to do that archaeology for me, once a week, and to email me the answers.

## Vision and what the app does

Who Made This? runs every Friday evening. It does three things.

**It attributes.** For each candidate resource it queries CloudTrail and pulls out the identity that created it, the API call they used, and the last time anything touched it. The email says "created by `arn:aws:sts::...:assumed-role/DevAdmin/rohan` via `CreateVolume` on 14 June" instead of just naming a volume ID.

**It scores.** Each resource gets an **Orphan Score** out of 100, built from five signals with fixed point values: no owner tag, no CloudTrail activity in 90 days, an idle shape such as a stopped instance or unattached volume, no infrastructure-as-code provenance, and a creating IAM identity that no longer exists. The email shows the arithmetic. I wanted a number I could argue with, not a model's opinion.

**It offers exactly two choices.** Every flagged resource in the digest has two links: **Keep** and **Send to Purgatory**.

Purgatory is the part I actually care about. It is a reversible middle state. A resource sent to Purgatory is stopped, its volumes are snapshotted, and it is tagged with a release date 30 days out. It shows up in every digest until then, with a one-click restore. If nobody claims it in 30 days, the app emails me a list and says: these look safe to delete now, go do it yourself.

Because the app cannot delete anything. Not "will not". Cannot. There is no `Delete*` and no `Terminate*` permission in any IAM policy in the stack. I checked last weekend's challenge comments and counted five idle-resource cleaners and four ownership-attribution tools among the 221 ideas people posted. Everything I saw either sent an alert or terminated the resource. The gap was the recoverable state in between, and the willingness to withhold the destructive permission from your own automation.

`[[SCREENSHOT: the digest email, showing Orphan Scores and the signal breakdown]]`

## How I built it

I gave myself Friday evening for setup and Saturday for the build, and the first decision was the one that mattered most.

**I dropped CloudTrail Lake, which was my original plan.** Two reasons. First, cost: Lake ingestion runs $0.75/GB on the one-year extendable retention option plus $0.005/GB scanned per query, and there is no free tier. Small money for a dev account, but not zero, and this challenge is about Free Tier. Second, and much worse, an event data store only captures events from the moment you create it. Creating one on Friday night gives you zero history to be an archaeologist about. The entire idea depends on looking backwards.

**CloudTrail Event history solved both problems.** It is on by default in every AWS account, it holds the last 90 days of management events, it is queryable through the `LookupEvents` API, and AWS charges nothing for viewing it. So I got 90 days of retroactive attribution, free, working the minute I deployed.

Then the 90 day boundary turned into the best signal in the whole app. If a resource exists and CloudTrail has no record of anything touching it in 90 days, that silence is stronger evidence of abandonment than any known creator. I called it **cold attribution** and gave it 25 points, the same weight as a missing owner tag. The limitation became the feature.

**There is no LLM in this app at all, and that was a deliberate reversal.** My original plan put Amazon Nova Lite on Bedrock in charge of writing the email summary. Then I asked what it was actually buying me. The answer was nicer prose in an email I send to myself, in exchange for a service dependency, an access request, a model ID to get wrong, and an output I could not reproduce. So I wrote `summarise()` in about twenty lines of plain Python instead. It counts the findings, names the top three by score, and states how many have cold attribution. Same account state, same sentence, every time.

That is the decision I would defend hardest. When you are building automation that touches infrastructure, every number in the output needs to be one you can explain to a colleague who is about to lose an instance. "Auditable and boring" beats "clever", and here it also meant one less thing to configure on a Friday night.

**The problem I did not see coming was authentication.** Clickable Keep and Purgatory links in an email mean an endpoint that acts on my AWS account with no login. My first instinct was Amazon Cognito, which is a lot of machinery for one person clicking one link. I used a Lambda Function URL with `AuthType: NONE`, and made the link itself the credential: each URL carries the resource ID, the action, an expiry timestamp, and an HMAC-SHA256 signature over all three. The signing key lives in SSM Parameter Store as a SecureString, which is free for standard parameters, unlike Secrets Manager at $0.40 per secret per month. Tamper with one character of the signature and you get a 403. The link dies when the grace window closes.

`[[SCREENSHOT: the 403 page from a tampered signature]]`

**Two smaller things that bit me.** `LookupEvents` throttles at roughly two requests per second, so a naive loop over 200 resources fails fast. I added exponential backoff and a 0.6 second pace between calls, which makes a full scan take about two minutes. Fine for weekly, wrong for an enterprise account, and I say so in the repo. Second, CloudTrail events are not instant. I spent twenty minutes debugging a scanner that was working perfectly, on a volume I had created four minutes earlier. Events typically show up within about fifteen minutes. Seed your test resources first, then go make coffee.

**Testing needed a real orphan.** An empty account produces an empty email, which is a terrible demo. So I created a genuinely abandoned 1 GiB volume and a stopped, untagged `t3.micro`, waited for CloudTrail to catch up, and ran the scanner. The round trip I care most about is flag, then Purgatory, then restore. That is the whole thesis in about twenty seconds.

Before pointing any of it at real resources, I stubbed every boto3 client and wrote an end-to-end test that needs no AWS account (`tests/test_e2e.py` in the repo). It asserts the exact Orphan Scores for a set of fixture resources, checks that a tampered, expired, resource-swapped or action-swapped signature is rejected, walks the full Purgatory round trip, and drives the enforcer through both a grace expiry and a Purgatory expiry. It caught a real bug: I was stopping the instance *before* snapshotting its volumes, which is the wrong order and would never have shown up in a manual click-through.

`[[SCREENSHOT: the Sent to Purgatory confirmation, then the Restored confirmation]]`
`[[SCREENSHOT or CLI OUTPUT: describe-snapshots showing the recovery snapshot, and describe-tags showing whomadethis:release-after]]`

## AWS services used and architecture overview

`[[EMBED: who-made-this-architecture.svg]]`

The flow, and how the agent is triggered:

1. **Amazon EventBridge Scheduler** fires the scanner on a weekly cron, Friday 18:00 IST. A second daily schedule fires the enforcer. Scheduler's free tier is 14 million invocations a month and is permanent, not a 12 month trial, so my forty invocations a month cost nothing.
2. **AWS Lambda** (Python 3.12 on arm64) runs three functions: `scanner`, `decide`, `enforcer`. All comfortably inside the 1M request and 400,000 GB-second monthly free tier.
3. **Amazon EC2 Describe APIs** provide the read-only inventory: instances, EBS volumes, Elastic IPs, unattached network interfaces. Four resource types, done properly, rather than thirty done badly.
4. **AWS CloudTrail Event history** via `LookupEvents` provides attribution across a 90 day window at no charge.
5. **Amazon DynamoDB** (on-demand) holds each finding and its state: `INFO`, `FLAGGED`, `KEEP`, `PURGATORY`, `RELEASABLE`. State is why the app never asks about the same resource twice.
6. **Amazon SES** sends the HTML digest with the signed decision links.
7. **A Lambda Function URL** is the decision endpoint. No API Gateway, no extra cost.
8. **AWS Systems Manager Parameter Store** holds the HMAC signing key as a free SecureString.
9. **AWS SAM** defines the whole thing, which matters because the IAM policies are the security model and I wanted them reviewable in one file.

`[[NOTE: the SES free tier of 3,000 message charges closed to new customers on 21 July 2026. If your account is newer than that, mention that you covered a few cents of SES from the $200 Free Tier credits.]]`

Total cost for the weekend: `[[YOUR ACTUAL NUMBER, mine was under a dollar]]`.

## What I learned

**A cheaper service can be the better service, not the compromise.** I assumed CloudTrail Lake was the grown-up choice and Event history was the toy. Event history was free, needed no setup, and gave me 90 days of retroactive data that Lake could not have given me at any price on a Friday night. I had never read the `LookupEvents` docs properly before this weekend.

**Withholding a permission is a product feature.** The strongest thing I can say about this app is what it cannot do. "Would you let a bot loose in your production account" stops being a worry the moment the answer is "it has no delete permission, here is the policy". I am going to reach for that pattern again.

**Design for the state between yes and no.** Alert-or-terminate is a false choice, and it is why cleanup tooling gets ignored. People do not ignore these emails because they are lazy. They ignore them because both buttons are scary. A reversible middle state with a visible undo makes the decision cheap, and cheap decisions actually get made.

**Not every app needs a model in it.** I went in assuming Bedrock would be a headline service and took it out halfway through, because the only job I had given it was writing prose I could generate deterministically. Removing it made the app easier to test, easier to explain, and impossible to configure wrongly. Adding an LLM should have to justify itself the same way any other dependency does.

**Test the destructive path before you point it at anything real.** I stubbed every boto3 client and wrote an end-to-end test that runs with no AWS account: full scan, score assertions, signature tampering, the Purgatory round trip, and the enforcer ageing a grace window out. It caught an ordering bug where I stopped the instance before snapshotting its volumes, which is exactly the wrong order and would have been invisible in a manual test.

**Honest limits, since somebody will ask.** Single region and single account, because `LookupEvents` is per-region. Four resource types, so none of the RDS, S3 or load balancer spend where the real money hides. Resources older than 90 days come back unattributed, which I score as a signal but which is still a gap. Elastic IPs and network interfaces are flagged but never modified, because releasing an EIP is not reversible and this app only does reversible things. DynamoDB reads use filtered scans, which is correct at this size and wrong at scale.

## Link to app and repo

**Repo:** `[[https://github.com/YOUR-USERNAME/who-made-this]]`

The repo has the SAM template, all three Lambda functions, the architecture diagram, and a README with deploy and teardown commands. There is no public hosted demo on purpose: a live demo of a tool that reads and stops resources would mean handing strangers access to an AWS account. The `[[SCREENSHOTS / VIDEO WALKTHROUGH]]` above show the full flag, Purgatory and restore cycle running against real resources in my account.

`[[OPTIONAL: 60 second video walkthrough link]]`

---

Shout-out to the builders in last weekend's thread who circled the same problem from different angles: Amrut's **Sweeper**, Sarvar Nadaf's **morning governance brief for agents**, Abhishek Tiwari's **Weekend Cloud Sweeper**, and Abdulsomad Abdulwahab's **NeverLeftOn**. Four of us independently landed on "attribute the forgotten resource to a human", which is a decent sign that the problem is real. If you built one of these, I would like to know whether you also ended up wanting a state between keep and kill.

#productivity
