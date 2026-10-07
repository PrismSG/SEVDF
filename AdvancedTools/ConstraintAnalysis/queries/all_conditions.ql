/**
 * @name All Conditions
 * @description Get all conditional branches in the codebase
 * @kind problem
 */
import cpp

/**
 * Get the actual span of a basic block using its start and end nodes.
 * This gives the logical flow boundaries, not the physical extent of all nodes.
 * This must match the function in all_basic_blocks.ql
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

from Function f, BasicBlock bb, BasicBlock truebb, BasicBlock falsebb
where bb.getEnclosingFunction() = f and
      bb.getATrueSuccessor() = truebb and
      bb.getAFalseSuccessor() = falsebb
select 
  f.getQualifiedName(),
  bb.getStart().getLocation().getFile().getRelativePath(),
  getBasicBlockId(bb),
  getBasicBlockId(truebb),
  getBasicBlockId(falsebb)