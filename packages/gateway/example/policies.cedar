// The coding agent may use the filesystem server...
permit (principal == Agent::"claude-code", action == Action::"call", resource)
when { context.upstream == "fs" };

// ...and Notion, through the developer's own account...
permit (principal == Agent::"claude-code", action == Action::"call", resource)
when { context.upstream == "notion" };

// ...where every change to the workspace asks a human first.
@approval("required")
permit (principal == Agent::"claude-code", action == Action::"call", resource)
when { context.upstream == "notion" && !(context.tool like "notion-search" || context.tool like "notion-fetch" || context.tool like "notion-get-*" || context.tool like "notion-query-*" || context.tool like "notion-list-*") };

// ...but never edit, move or create files or directories.
forbid (principal, action == Action::"call", resource)
when { context.tool like "edit*" || context.tool like "move*" || context.tool like "create*" };

// Tegata: content read from files may flow into notes.md without asking.
@grant("notes")
permit (principal == Agent::"claude-code", action == Action::"flow", resource == Tool::"fs.write_file")
when { context.source like "fs.read_*" && context.args has path && context.args.path == "notes.md" };
