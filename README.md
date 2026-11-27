# mew-ci-scratch

Scratch CI repo for `871554520/mew-recomp`.

Purpose: run jobs that are queue-limited on the main repo (macOS runners, arm64
cross builds) and stage3 rounds that must not cancel the main repo's
`stage3-full` concurrency group.

Workflows here check out the real repo at a chosen ref:

```yaml
- uses: actions/checkout@v4
  with:
    repository: 871554520/mew-recomp
    ref: <sha-or-branch>
```

`ping` is a queue probe: one ubuntu job + one macos-15 job, to see whether the
new account gets a macOS runner slot.
