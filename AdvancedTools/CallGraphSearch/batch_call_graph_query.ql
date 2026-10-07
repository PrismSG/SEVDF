/**
 * Batch Call Graph Query
 * Extract all function call relationships in the codebase at once
 * This can be used to pre-populate the call graph cache
 */

import cpp

from Function caller, Function callee, FunctionCall fc
where 
  fc.getTarget() = callee and
  fc.getEnclosingFunction() = caller and
  // Filter out some noise
  not caller.isCompilerGenerated() and
  not callee.isCompilerGenerated() and
  // Optionally filter by file patterns
  // caller.getFile().getRelativePath().matches("%src/%") and
  // callee.getFile().getRelativePath().matches("%src/%")
  exists(caller.getFile().getRelativePath()) and
  exists(callee.getFile().getRelativePath())
select 
  caller.getName() as caller_name,
  caller.getFile().getRelativePath() as caller_file,
  caller.getLocation().getStartLine() as caller_line,
  callee.getName() as callee_name, 
  callee.getFile().getRelativePath() as callee_file,
  callee.getLocation().getStartLine() as callee_line,
  fc.getLocation().getStartLine() as call_site_line