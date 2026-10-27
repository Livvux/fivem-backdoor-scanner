# Reporting a missed backdoor

If you found a backdoor family the rules do not catch and publishing the pattern
would help attackers before a fix exists, do not open a public issue. Use GitHub's
private vulnerability reporting: on this repository, open the **Security** tab and
choose **Report a vulnerability**.

The maintainer has to enable this under repository **Settings → General → Security →
Private vulnerability reporting**. If the button is missing, the feature is still off.

Include:

- a defanged snippet or a description of the pattern,
- which rule you expected to fire,
- whether the backdoor is still active (C2 reachable).

We aim to answer within 7 days and to publish the rule with credit to you, unless you
prefer to stay anonymous. Do not include live malware. Send a defanged snippet or a
description of the pattern.
