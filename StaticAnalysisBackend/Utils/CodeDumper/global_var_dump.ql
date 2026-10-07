/**
 * @kind problem
 * @name Global Variable Definitions
 * @id cpp/global-variable-definitions
 * @description Lists global variable definitions with their locations.
 */

import cpp

from GlobalVariable gv
where gv.hasDefinition()
  and gv.getLocation().getFile().getAbsolutePath().indexOf("usr/include") = -1  // Exclude system headers
select gv.getName().toString(),
       gv.getQualifiedName().toString(),
       gv.getType().toString(),
       gv.getLocation().getFile().getAbsolutePath().toString(),
       gv.getLocation().getStartLine().toString(),
       gv.getLocation().getEndLine().toString()
