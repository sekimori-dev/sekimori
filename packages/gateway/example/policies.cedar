// The coding agent may use the filesystem server...
permit (principal == Agent::"claude-code", action == Action::"call", resource)
when { context.upstream == "fs" };

// ...but never edit, move or create files,
forbid (principal, action == Action::"call", resource)
when { context.tool like "edit*" || context.tool like "move*" || context.tool like "create*" };

// and write only to notes.md.
forbid (principal, action == Action::"call", resource == Tool::"fs.write_file")
unless { context.args has path && context.args.path == "notes.md" };

// Tegata: content read from files may flow into notes.md without asking.
@grant("notes")
permit (principal == Agent::"claude-code", action == Action::"flow", resource == Tool::"fs.write_file")
when { context.source like "fs.read_*" && context.args has path && context.args.path == "notes.md" };
