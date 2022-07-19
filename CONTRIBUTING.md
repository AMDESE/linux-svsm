# Contribution and style

Contributions are expected in the form of GitHub pull requests. They will
need to be reviewed and accepted by a maintainer.

Contributions must include a "Signed-off-by" line containing the
contributor's name and e-mail to every commit message. The addition of this
line attests that the contributor has read and agrees with the [Developer
Certificate of Origin](https://developercertificate.org/).

If significant changes must be made before accepting a pull request, it
will be preferable to open a new pull request with clean commits.

If your patch fixes a bug in a specific commit, please use the ‘Fixes:’ tag
with the first 7 characters of the commit hash, and the one line summary.
For example:

```
Fixes: 3541fad ("IDT: include new vector entry #HV")
```

If the patch was created with the help of other developer(s), the tag
"Co-Developed-by:" can be included. The co-developers will also need to
have a Signed-off-by line.

Commits will be tagged when the maintainers consider there is something
worth tagging. Similarly, new branches will be created if needed.

## Code style

Code contributions should adhere to rustfmt, like in the Rust for Linux
kernel project. You can check with:

```
# rustfmt --check <file>
```
Besides that, we only ask for:

1. Variable definitions to be explicit on type. For example:

```rust
let a: u64 = 4;
```

2. Constant definitions to include a comment with their value (for
documentation purposes). For example:

```rust
/// 16
const GUID_SIZE: u64 = 16;
```
