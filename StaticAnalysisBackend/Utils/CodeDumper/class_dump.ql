/**
 * @kind problem
 * @name Class and Struct Definitions
 * @id cpp/class-struct-definitions
 * @description Lists class, struct, and union definitions with their locations.
 */

import cpp

from Class c
where c.hasDefinition()
  and c.getLocation().getFile().getAbsolutePath().indexOf("usr/include") = -1  // Exclude system headers
select c.getName().toString(),
       c.getQualifiedName().toString(),
       c.getLocation().getFile().getAbsolutePath().toString(),
       c.getLocation().getStartLine().toString(),
       c.getLocation().getEndLine().toString()
