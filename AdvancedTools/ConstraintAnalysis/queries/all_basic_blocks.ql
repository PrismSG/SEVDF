/**
 * @name All Basic Blocks
 * @description Get all basic blocks with their function information
 * @kind problem
 */
import cpp

/**
 * Get the actual span of a basic block using its start and end nodes.
 * This gives the logical flow boundaries, not the physical extent of all nodes.
 */
string getBasicBlockId(BasicBlock bb) {
  exists(ControlFlowNode start, ControlFlowNode end |
    start = bb.getStart() and
    end = bb.getEnd() and
    result = start.getLocation().getStartLine() + "." + start.getLocation().getStartColumn() + 
             "_" + 
             end.getLocation().getEndLine() + "." + end.getLocation().getEndColumn()
  )
}

from Function f, BasicBlock bb, string isEntry, string isExit
where bb.getEnclosingFunction() = f and
      (if bb = f.getEntryPoint() then isEntry = "true" else isEntry = "false") and
      (if not exists(bb.getASuccessor()) then isExit = "true" else isExit = "false")
select 
  f.getQualifiedName(),
  f.getFile().getRelativePath(),
  getBasicBlockId(bb),
  isEntry,
  isExit