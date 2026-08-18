# GaslightCTF 2026 — Messageboard Writeup

## Summary

The story field was not the useful injection point. Stories are rendered as escaped React text, and user-submitted stories are normalized before storage. The exploitable behavior was the hidden sort parameter:

~~~text
/api/stories?column=secret&order=ASC
~~~

The server accepts secret as a sort column and returns usernames in that order. Creating accounts with chosen passwords turns the endpoint into a comparison oracle for the admin password.

Recovered admin secret:

~~~text
b0a0dc68a347b984
~~~

Flag:

~~~text
gaslightCTF{ar3_y0u_my_cl0s3_fr13nd_n0w?_59a0c6f683a7}
~~~

## Initial source review

Stories are rendered in App.tsx as a normal React child:

~~~tsx
<p className="break-words whitespace-pre-wrap">{s.story}</p>
~~~

React therefore escapes HTML and JavaScript. There is no dangerouslySetInnerHTML, eval, shell execution, or file-read API.

User stories are passed through clean(story) before being interpolated into the update query. The cleaner preserves only whitespace-separated words made entirely of ASCII letters and digits. Thus:

~~~text
hello world! :) <script>
~~~

becomes approximately:

~~~text
hello
~~~

The punctuation in the seeded admin and Carol stories is not a bypass: those rows are inserted during startup by seed() using str(), without calling clean().

## The vulnerable sort parameter

The API validates column only by checking that it contains alphanumeric characters. It does not use an allowlist, and then interpolates it into SQL:

~~~sql
ORDER BY <column> <order>
~~~

The UI offers only name and expiry, but the HTTP API accepts:

~~~text
column=secret
~~~

The response includes each row’s author, so the otherwise-hidden order of the secret column becomes observable.

For a probe account with chosen secret C, and unknown admin secret S:

- admin before the probe implies S < C;
- the probe before admin implies S > C.

This is an ordering/comparison oracle, not a direct SQL dump.

## Mathematical keyspace

The seed generates secrets with:

~~~ts
crypto.getRandomValues(new Uint8Array(8)).toHex()
~~~

Eight random bytes contain 64 random bits:

~~~text
8 bytes × 8 bits = 64 bits
~~~

Hex encoding produces 16 characters, with 16 choices per character:

~~~text
16^16
= (2^4)^16
= 2^64
= 18,446,744,073,709,551,616 possible secrets
~~~

16 × 16 = 256 applies only to two hexadecimal characters, which represent one byte. It is not the keyspace of all 16 characters.

## Binary-search method

Interpret the hexadecimal secret as an integer:

~~~text
0 ≤ S ≤ 2^64 - 1
~~~

Start with:

~~~text
low  = 0
high = 2^64 - 1
~~~

For each step:

~~~text
mid = floor((low + high) / 2)
candidate = 16-digit hexadecimal representation of mid
~~~

Create a disposable account whose password is candidate, post a public story, and request the feed sorted by secret.

Update the interval:

~~~text
if admin appears before the probe:
    high = mid - 1
else:
    low = mid + 1
~~~

Each comparison halves the remaining space:

~~~text
2^64 → 2^63 → 2^62 → ... → 2^0
~~~

Therefore the maximum number of comparisons is:

~~~text
log2(2^64) = 64
~~~

This is binary search over the full 64-bit value, not meet-in-the-middle. No two key halves are matched.

## Selected search steps

The first comparisons on the replacement instance were:

| Step | Candidate | Result | Remaining interval |
|---:|---|---|---|
| 1 | 7fffffffffffffff | admin after probe | 8000000000000000 .. ffffffffffffffff |
| 2 | bfffffffffffffff | admin before probe | 8000000000000000 .. bffffffffffffffe |
| 3 | 9fffffffffffffff | admin after probe | a000000000000000 .. bffffffffffffffe |
| 4 | afffffffffffffff | admin after probe | b000000000000000 .. bffffffffffffffe |
| 5 | b7ffffffffffffff | admin before probe | b000000000000000 .. b7fffffffffffffe |
| 6 | b3ffffffffffffff | admin before probe | b000000000000000 .. b3fffffffffffffe |
| 7 | b1ffffffffffffff | admin before probe | b000000000000000 .. b1fffffffffffffe |
| 8 | b0ffffffffffffff | admin before probe | b000000000000000 .. b0fffffffffffffe |

Near the end, the interval narrowed to:

~~~text
b0a0dc68a347b984 .. b0a0dc68a347b984
~~~

The value was verified by logging in as admin and requesting admin-visible stories. The equality probe sorted adjacent to admin because both records had the same secret; the successful login confirmed the result.

## Runtime process and findings

### First target instance

- Confirmed the homepage and API were reachable.
- Confirmed the deployed client bundle matched the supplied source.
- Logged in as seeded bob with password iamthebuilder.
- Confirmed Bob could see Carol’s close-friends story but not admin’s close-friends story.
- Tested a disposable punctuation story; it was normalized by the deployed server.
- Confirmed the secret sort behavior.

That target was then replaced with a new instance.

### Replacement target instance

- Revalidated the homepage, Bob login, and column=secret ordering.
- An initial long oracle run created 20 zord##probe accounts before the execution window ended.
- The search was resumed in eight-comparison batches using 64 zbs##probe accounts.
- The final secret was recovered and verified with an admin login.

Recorded totals for the replacement instance were approximately:

~~~text
84 oracle comparisons performed
64 comparisons used by the final binary search
84 probe accounts created
268 successful HTTP requests
~~~

The extra 20 comparisons came from the interrupted/restarted attempt. Probe stories were configured to expire after about one hour. No source files were modified.

## Remediation

Use a strict allowlist for sortable columns:

~~~ts
const allowedColumns = new Set(["name", "expiry"]);
~~~

Never allow clients to sort by password or secret fields. Passwords should also be stored as salted hashes, and SQL values should use parameterized queries rather than string interpolation.
