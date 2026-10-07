/**
 * @kind problem
 * @name Macro Use-Def
 * @id cpp/macro-use-def
 * @description Maps macro usages to their definitions.
 */

import cpp

from MacroInvocation mi, Macro m
where mi.getMacro() = m
  and not mi.getLocation().getFile().getAbsolutePath().matches("%/usr/include/%")
select 
  m.getName(),
  mi.getLocation().getFile().getAbsolutePath(),
  mi.getLocation().getStartLine(),
  m.getLocation().getFile().getAbsolutePath(),
  m.getLocation().getStartLine(),
  "#define " + m.getHead() + " " + m.getBody()
