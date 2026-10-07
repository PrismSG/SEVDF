/**
 * CodeQL query: simplified function-call relationship check
 * 
 * Check whether the call on the specified line invokes the target function
 */

import cpp
import semmle.code.cpp.pointsto.CallGraph

/**
 * Main query: check the function-call relationship directly
 */
from Call call, Function caller, Function callee,
     string callerName, int toLine, string toLocation, string calleeName
where
  // Set query parameters to the actual values
  callerName = "main" and              // Replace with the caller function name
  toLine = 123 and                     // Replace with the call line number
  toLocation = "src/main.cpp" and      // Replace with the caller file path
  calleeName = "calculateSum" and      // Replace with the callee function name
  
  // 1. Find the caller function
  caller.getName() = callerName and
  (
    caller.getLocation().getFile().getAbsolutePath().matches("%" + toLocation + "%") or
    caller.getLocation().getFile().getBaseName().matches("%" + toLocation + "%") or
    caller.getLocation().getFile().getAbsolutePath().matches("%" + toLocation) or
    caller.getLocation().getFile().getBaseName().matches("%" + toLocation)
  ) and
  
  // 2. Find the callee function
  callee.getName() = calleeName and
  
  // 3. Find the call at the specified line in the caller
  call.getEnclosingFunction() = caller and
  call.getLocation().getStartLine() = toLine and
  
  // 4. Verify the call relationship
  call.getTarget() = callee

select call, caller, callee,
  "Line " + toLine + " in " + callerName + "() calls " + calleeName + "()",
  call.getLocation(),
  callee.getLocation()
 
 /**
  * Boolean-result query: return true or false
  */
 /*
 select 
   exists(Call call, Function caller, Function callee |
     verifySimpleCallRelation("main", 123, "src/main.cpp", "calculateSum", call, caller, callee)
   ) as "CallExists"
 */
