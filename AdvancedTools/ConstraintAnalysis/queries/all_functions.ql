/**
 * @name All Functions
 * @description Get all functions in the codebase
 * @kind problem
 */
import cpp

from Function f
select 
  f.getQualifiedName(),
  f.getFile().getRelativePath(),
  f.getLocation().getStartLine(),
  f.getLocation().getEndLine(),
  f.getBlock().getLocation().getStartLine().toString() + "." +    
  f.getBlock().getLocation().getStartColumn().toString() + "_" +
  f.getBlock().getLocation().getEndLine().toString() + "." + 
  f.getBlock().getLocation().getEndColumn().toString()