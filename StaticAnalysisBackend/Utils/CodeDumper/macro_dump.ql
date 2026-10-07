/**
 * @kind problem
 * @name Macro Definitions
 * @id cpp/macro-definitions
 * @description Lists macro definitions with their locations and bodies.
 */

import cpp

from Macro m
where not m.getLocation().getFile().getAbsolutePath().matches("%/usr/include/%")
select m.getName(),
       "#define " + m.getHead() + " " + m.getBody(),
       m.getLocation().getFile().getAbsolutePath(),
       m.getLocation().getStartLine(),
       m.getLocation().getEndLine()
