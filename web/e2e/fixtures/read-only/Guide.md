# Welcome to Crabinet

This deterministic fixture demonstrates the safe **GitHub Flavored Markdown** reader.

- Browse isolated shared folders
- Preview source without executing it
- Keep access grants visible

> [!NOTE]
> Grants are checked again on every request.

| Grant  | Read | Write |
| :----- | :--: | :---: |
| Reader | yes  |  no   |
| Writer | yes  |  yes  |

- [x] Signed in
- [ ] Uploaded a file

```rust
fn main() {
    println!("hello");
}
```

<details><summary>Hostile content</summary>

<script>window.__indexHostileScript = true</script>

![external beacon](https://attacker.invalid/markdown-pixel)

[unsafe link](javascript:window.__indexJavascriptLink=true)

<form action="/api/v1/auth/logout"><button>Unsafe form</button></form>

</details>
