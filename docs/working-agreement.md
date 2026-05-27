# Turan Working Agreement

These are the collaboration rules for building Turan:

1. Comments should be short working notes, not tutorial prose.
2. If a comment is needed, keep it close to the line and practical.
3. Use comments for the lines that need a nudge, not for everything.
4. Prefer code that reads clearly on its own.
5. Function names should sound natural to a human.
6. If a function name is unclear, ask before creating it.
7. When asking about a function name, explain the function's purpose first.
8. Every file should be used and connected to the app.
9. Avoid placeholder functions that leave a file empty or disconnected.
10. Prefer small, purposeful files over unused structure.

Comment style examples:

- Good: `# normalize input`
- Good: `# check v1 headers`
- Bad: `# We normalize the input first so the rest of the scan can trust one canonical URL.`
- Bad: `# We focus on a short list of headers that are easy to verify and easy to explain to users.`
