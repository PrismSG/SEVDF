/**
 * @kind problem
 * @name Function Use-Def
 * @id cpp/function-use-def
 * @description Maps function calls to their definitions.
 */

import cpp

from FunctionCall fc, Function f
where fc.getTarget() = f
  and f.hasDefinition()
  and not fc.getLocation().getFile().getAbsolutePath().matches("%/usr/include/%")
select 
  f.getName(),
  f.getQualifiedName(),
  fc.getLocation().getFile().getAbsolutePath(),
  fc.getLocation().getStartLine(),
  f.getBlock().getLocation().getFile().getAbsolutePath(),
  f.getLocation().getStartLine(),
  f.getBlock().getLocation().getEndLine()
