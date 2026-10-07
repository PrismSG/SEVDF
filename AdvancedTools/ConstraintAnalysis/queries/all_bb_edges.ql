/**
 * @name All Basic Block Edges
 * @description Get all edges between basic blocks
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

from Function f, BasicBlock bb, BasicBlock succ, string edgeType
where bb.getEnclosingFunction() = f and
      succ = bb.getASuccessor() and
      (if bb.getATrueSuccessor() = succ then edgeType = "TRUE" 
       else if bb.getAFalseSuccessor() = succ then edgeType = "FALSE"
       else edgeType = "UNCONDITIONAL")
select 
  f.getQualifiedName(),
  getBasicBlockId(bb),
  getBasicBlockId(succ),
  edgeType