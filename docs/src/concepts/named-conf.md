# named.conf Format

`named.conf` is the main configuration file for BIND9. It consists of a sequence of
**statements**, each terminated with a semicolon (`;`). Statements can be nested inside
**blocks** delimited by `{ }`.

---

## Statement types

Hornet parses the following top-level statements:

### `options { … };`

Global server options. Controls recursion, forwarders, listen addresses, DNSSEC,
rate limiting, logging, and more.

```text
options {
    directory "/var/cache/bind";
    recursion yes;
    allow-query { any; };
    forwarders { 8.8.8.8; 8.8.4.4; };
    forward only;
    dnssec-validation auto;
};
```

### `zone "name" [class] { … };`

Defines a DNS zone. The zone type determines its role:

| Type | Keyword | Description |
|---|---|---|
| Primary | `primary` (or `master`) | Authoritative source; has a zone file |
| Secondary | `secondary` (or `slave`) | Receives zone transfers from a primary |
| Stub | `stub` | Caches only NS records for a zone |
| Forward | `forward` | Forwards queries for this zone to specific servers |
| Hint | `hint` | Root hints zone |
| Redirect | `redirect` | Intercepts queries and returns alternate answers |
| Static stub | `static-stub` | Stub zone with configured server addresses |
| Delegation only | `delegation-only` | Enforces delegation-only responses (removed in BIND 9.20) |
| In view | `in-view "view-name";` | Shares a zone defined in another view (an option, not a `type`) |

A zone or view may name its class after the name: `IN` (the default), `CH` / `CHAOS`,
`HS` / `HESIOD` or `ANY`. A zone inside a view without a class inherits the view's class.

```text
zone "example.com" {
    type primary;
    file "/etc/bind/zones/example.com.db";
    allow-transfer { 192.0.2.2; };
};

zone "example.com" IN {
    type secondary;
    primaries { 192.0.2.1; };
    file "/var/cache/bind/example.com.db";
};
```

### `view "name" [class] { … };`

Groups zones and options for specific client sets. Used for split-horizon DNS.

```text
view "internal" {
    match-clients { 10.0.0.0/8; };
    zone "example.com" {
        type primary;
        file "/etc/bind/zones/example.com.internal.db";
    };
};

view "external" {
    match-clients { any; };
    zone "example.com" {
        type primary;
        file "/etc/bind/zones/example.com.external.db";
    };
};
```

### `acl "name" { … };`

Defines a named address match list for reuse in other statements.

```text
acl "trusted" {
    10.0.0.0/8;
    192.168.0.0/16;
    localhost;
};
```

### `logging { … };`

Configures log channels and categories.

```text
logging {
    channel "default_log" {
        file "/var/log/named/default.log" versions 3 size 5m;
        severity dynamic;
        print-time yes;
        print-severity yes;
        print-category yes;
    };
    category default { "default_log"; };
    category queries { "default_log"; };
};
```

### `controls { … };`

Defines control channels for `rndc` access.

```text
controls {
    inet 127.0.0.1 port 953 allow { 127.0.0.1; } keys { "rndc-key"; } read-only no;
    unix "/run/named/rndc.sock" perm 0600 owner 0 group 0;
};
```

`perm`, `owner` and `group` accept C-style numbers (`0600` octal, `0x180` hex, `384`
decimal). The writer prints them in decimal, as BIND9 does. `unix` control channels were
removed in BIND 9.20; hornet still parses and writes them for older configurations.

### `key "name" { … };`

Defines a TSIG key for authenticated DNS operations.

```text
key "rndc-key" {
    algorithm hmac-sha256;
    secret "base64-encoded-secret==";
};
```

### `primaries / masters "name" { … };`

Defines a named list of primary servers for reuse in zone statements.

```text
primaries "primary-servers" {
    192.0.2.1 key "transfer-key";
    192.0.2.2;
};

zone "example.com" {
    type secondary;
    primaries { "primary-servers"; };
};
```

### `server addr { … };`

Per-server configuration options such as TSIG keys and transfer settings.

```text
server 192.0.2.1 {
    keys { "transfer-key"; };
    transfers 10;
};
```

### `include "path";`

Inserts the contents of another file at this point.

```text
include "/etc/bind/named.conf.local";
```

---

## Address Match Lists

Many directives accept an **address match list** (AML) — a set of:

- IPv4/IPv6 addresses or CIDR prefixes: `192.168.1.0/24`
- Named ACL references: `trusted`
- Built-in ACLs: `any`, `none`, `localhost`, `localnets`
- TSIG key references: `key "my-key"`
- Negation: `!192.168.1.0/24`

```text
allow-query {
    localhost;
    10.0.0.0/8;
    !192.168.1.100;
    "trusted";
};
```

The built-ins `any`, `none`, `localhost` and `localnets` are recognised only as whole,
unquoted words. `anyone` is a reference to an ACL named `anyone`, and a quoted `"any"` is
a reference to an ACL named `any`, not the built-in. When writing, hornet quotes an ACL
reference whose name is a reserved word (`any`, `none`, `localhost`, `localnets`, `key`)
or is not a plain name, so it keeps that meaning.

An empty list is written as `{ }`.

---

## Legacy keyword aliases

BIND9 supports legacy BIND8 keywords that Hornet recognises during parsing and can
optionally modernise when writing:

| Legacy | Modern |
|---|---|
| `master` | `primary` |
| `slave` | `secondary` |

Use `WriteOptions { modern_keywords: true }` (the default) or the `hornet convert` command
to normalise a config file to modern keywords.

---

## Unknown blocks and unmodelled options

Hornet preserves any top-level statement it does not recognise verbatim using the
`Statement::Unknown { keyword, raw }` variant. Its end is found with quotes and comments
taken into account, so a `;` or `}` inside a string or comment does not cut it short. This
ensures unknown or future BIND9 constructs do not cause parse failures.

Inside `options`, `zone`, `view` and `server` blocks, an option hornet does not model, or
a modelled option whose value falls outside its typed grammar, is kept as a
`(key, value)` pair in the block's `extra` list.

!!! danger "Trusted text only"
    `Statement::Unknown` and `extra` are written back verbatim, with no escaping. They are
    safe for text read from a trusted file, but anything placed in them reaches BIND9 as
    configuration. See
    [Raw carriers hold trusted text only](../guide/writing.md#raw-carriers-hold-trusted-text-only).

---

## Next Steps

- [Zone Files](./zone-files.md) — Zone file format and record types
- [Parsing Guide](../guide/parsing.md) — How to use the parser in code
- [named.conf Constructs Reference](../reference/named-conf-constructs.md) — Complete field listing
