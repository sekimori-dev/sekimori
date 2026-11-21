// The coding agent may use the filesystem server...
permit (principal == Agent::"claude-code", action == Action::"call", resource)
when { context.upstream == "fs" };

// ...but never change files.
forbid (principal, action, resource)
when {
  context.tool like "write*" ||
  context.tool like "edit*" ||
  context.tool like "move*" ||
  context.tool like "create*"
};
