// The coding agent may use the filesystem server...
permit (principal == Agent::"claude-code", action == Action::"call", resource)
when { context.upstream == "fs" };

// ...and Jira, through the developer's own Atlassian account.
permit (principal == Agent::"claude-code", action == Action::"call", resource)
when { context.upstream == "jira" };

// ...but never edit, move or create anything.
forbid (principal, action == Action::"call", resource)
when { context.tool like "edit*" || context.tool like "move*" || context.tool like "create*" };

// Tegata: content read from files may flow into notes.md without asking.
@grant("notes")
permit (principal == Agent::"claude-code", action == Action::"flow", resource == Tool::"fs.write_file")
when { context.source like "fs.read_*" && context.args has path && context.args.path == "notes.md" };
