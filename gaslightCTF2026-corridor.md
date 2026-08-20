# GaslightCTF — Corridor Writeup

## Reconnaissance

The root page returned a `correct` page containing two transparent links:

```html
<a id="l" href="l/"></a>
<a id="r" href="r/"></a>
```

Requests were made with the required header:

```http
X-LLM-Agent: GPT-5 Codex / Codex
```

For example:

```bash
curl -k \
  -H 'X-LLM-Agent: GPT-5 Codex / Codex' \
  https://8f14e17c-d4e0-4540-839e-1d5cae802681.play.gaslightctf.cooking:1337/
```

## Following the Correct Path

At each level, one branch returned a page titled `correct`; the other returned `wrong`.

The branches encode binary values:

```text
l/ = 0
r/ = 1
```

I followed the correct branch sequentially, testing `l/` first and testing `r/` only when the left branch was wrong. The resulting bits were grouped into bytes and decoded as ASCII.

The beginning of the stream was:

```text
01100111 01100001 01110011 01101100 01101001 01100111 01101000 01110100
```

which decodes to:

```text
gaslight
```

The full process can be automated with:

```python
import requests

BASE = "https://8f14e17c-d4e0-4540-839e-1d5cae802681.play.gaslightctf.cooking:1337/"
HEADERS = {"X-LLM-Agent": "GPT-5 Codex / Codex"}

bits = ""
url = BASE

while True:
    response = requests.get(url + "l/", headers=HEADERS, verify=False)

    if "<title>correct</title>" in response.text:
        bits += "0"
        url += "l/"
        continue

    response = requests.get(url + "r/", headers=HEADERS, verify=False)

    if "<title>correct</title>" in response.text:
        bits += "1"
        url += "r/"
        continue

    break

decoded = bytes(
    int(bits[i:i + 8], 2)
    for i in range(0, len(bits) - 7, 8)
).decode()

print(decoded)
```

## Flag

```text
gaslightCTF{fr33d0m_4t_l4st_f77a33cd4f1c}
```

The challenge is a binary-choice path oracle: the server reveals one valid branch at every level, allowing the flag to be reconstructed bit-by-bit and decoded as ASCII.
